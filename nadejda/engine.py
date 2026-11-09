"""The Nadejda engine: nftables + NFQUEUE + desync + DNS."""

from __future__ import annotations

import logging
import os
import queue
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import replace

from .config import Config
from .desync import (
    PRESETS,
    Step,
    Strategy,
    UDPStrategy,
    build_plan,
    build_udp_plan,
    port_in_ranges,
)
from .dnsserver import DNSServer
from .firewall import Firewall, FirewallConfig
from .hostlist import HostList
from .nfqueue import NF_ACCEPT, NF_DROP, NFQueue
from .packet import (
    TCP_ACK,
    TCP_PSH,
    Packet,
    UDPPacket,
    build_reset,
    build_segment,
    looks_like_client_hello,
    make_client_hello,
    make_fake_client_hello,
    parse_client_hello,
    parse_packet,
    parse_udp_packet,
    split_payload,
)
from .resolver import Resolver

log = logging.getLogger(__name__)

IPPROTO_RAW = 255
IPV6_HDRINCL = 36
IP_HDRINCL = 3

# A flow is treated as black-holed when the client re-sends exactly the same
# bytes at least STALL_REPEATS times and at least STALL_MIN_AGE seconds have
# passed since the first attempt.  Healthy retransmissions recover after one
# or two tries, so this never fires on ordinary packet loss.
STALL_MIN_AGE = 1.0
STALL_REPEATS = 3
FLOW_TTL = 180.0

# At startup, sockets that predate Nadejda may already be black-holed: the
# provider dropped the flow and the application is waiting for the 15-minute
# TCP timeout.  A socket is considered dead when the server has acknowledged
# nothing but the SYN, the client is in retransmission backoff, and nothing
# has arrived for a few seconds.
STUCK_MIN_IDLE_MS = 5000
STUCK_MIN_BACKOFF = 1

_HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"PRI * HTTP/2.0",
)


def _looks_like_http(payload: bytes) -> bool:
    return payload.startswith(_HTTP_METHODS)


def _tls_record_len(payload: bytes) -> int | None:
    """Total TLS record length (header included) or None if not a TLS record."""
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    return 5 + int.from_bytes(payload[3:5], "big")


def _signed_delta(a: int, b: int) -> int:
    """Signed distance between two 32-bit TCP sequence numbers."""
    delta = (a - b) & 0xFFFFFFFF
    return delta - 0x100000000 if delta >= 0x80000000 else delta


class Sender:
    """Emits raw IP packets from a small worker pool."""

    def __init__(self, mark: int, workers: int = 4, maxsize: int = 2048):
        self.mark = mark
        self.workers = workers
        self.queue: queue.Queue[list[Step] | None] = queue.Queue(maxsize=maxsize)
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._raw4: socket.socket | None = None
        self._raw6: socket.socket | None = None
        self.sent = 0
        self.failed = 0

    def start(self) -> None:
        try:
            raw4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_RAW)
            raw4.setsockopt(socket.IPPROTO_IP, IP_HDRINCL, 1)
            raw4.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, self.mark)
            self._raw4 = raw4
        except (OSError, PermissionError) as exc:
            raise RuntimeError(f"cannot create a marked raw socket: {exc}") from exc
        try:
            raw6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_RAW)
            raw6.setsockopt(socket.IPPROTO_IPV6, IPV6_HDRINCL, 1)
            raw6.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, self.mark)
            self._raw6 = raw6
        except OSError:
            self._raw6 = None
            log.warning("IPv6 raw sockets unavailable, IPv6 desync disabled")
        for index in range(self.workers):
            thread = threading.Thread(target=self._worker, name=f"desync-{index}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def available(self, version: int) -> bool:
        """True when a raw socket exists for this IP version."""
        return self._raw4 is not None if version == 4 else self._raw6 is not None

    def submit(self, plan: list[Step]) -> bool:
        try:
            self.queue.put_nowait(plan)
            return True
        except queue.Full:
            return False

    def send_now(self, plan: list[Step]) -> bool:
        """Send a plan synchronously, before the caller returns its verdict.

        Used for Discord voice: the fakes must be on the wire before the
        kernel forwards the original datagram, and the original must not be
        dropped and re-sent (that adds jitter to real-time audio).
        """
        for step in plan:
            if step.delay_ms:
                time.sleep(step.delay_ms / 1000.0)
            for raw in step.packets:
                self._send(raw)
        return True

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                plan = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if plan is None:
                return
            for step in plan:
                if self._stop.is_set():
                    return
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000.0)
                for raw in step.packets:
                    self._send(raw)

    def _send(self, raw: bytes) -> None:
        version = raw[0] >> 4
        try:
            if version == 4 and self._raw4 is not None:
                dst = socket.inet_ntoa(raw[16:20])
                self._raw4.sendto(raw, (dst, 0))
            elif version == 6 and self._raw6 is not None:
                dst = socket.inet_ntop(socket.AF_INET6, raw[24:40])
                self._raw6.sendto(raw, (dst, 0))
            else:
                self.failed += 1
                return
            self.sent += 1
        except OSError as exc:
            self.failed += 1
            log.debug("raw send failed: %s", exc)

    def stop(self) -> None:
        self._stop.set()
        for _ in self._threads:
            try:
                self.queue.put_nowait(None)
            except queue.Full:
                pass
        for thread in self._threads:
            thread.join(timeout=2)
        for sock in (self._raw4, self._raw6):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass


class Engine:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.general = cfg.general
        self.strategy = cfg.strategy
        self.udp_strategy: UDPStrategy = cfg.udp.clone()
        self.hosts = HostList(cfg.domains)
        self.excluded = HostList(cfg.exclude)
        self.force_tcp = HostList(self.udp_strategy.force_tcp_domains)
        self.resolver = Resolver(
            cfg.general.dns_upstreams,
            mark=cfg.mark,
            fallback_udp=cfg.general.dns_fallback_udp,
        )
        self.firewall = Firewall(
            FirewallConfig(
                queue_num=cfg.general.queue_num,
                mark=cfg.mark,
                scope=cfg.general.scope,
                quic=cfg.general.quic,
                block_quic=cfg.general.block_quic,
                quic_force_tcp=bool(self.force_tcp),
                dns=cfg.general.dns,
                dns_port=cfg.general.dns_port,
                tcp_ports=tuple(cfg.general.tcp_ports),
                udp_voice_ports=tuple(cfg.general.udp_voice_ports),
                tcp_cutoff=cfg.general.tcp_cutoff,
                udp_cutoff=cfg.general.udp_cutoff,
                game_filter=cfg.general.game_filter,
                game_tcp_ports=cfg.general.game_tcp_ports,
                game_udp_ports=cfg.general.game_udp_ports,
            )
        )
        self.queue = NFQueue(cfg.general.queue_num)
        self.sender = Sender(cfg.mark)
        self.dns: DNSServer | None = None
        self.stop_event = threading.Event()
        self.decoy = make_client_hello(
            cfg.strategy.fake_sni, min_len=max(700, cfg.strategy.seqovl + 200)
        )
        self.fake_decoy = make_fake_client_hello(cfg.strategy.fake_sni)
        # Per-domain strategies, longest suffix first so api-v2.foo.com can
        # override foo.com without changing the lookup code.
        self.overrides: list[tuple[str, Strategy, bytes, bytes]] = []
        for domain, preset in sorted(
            cfg.overrides.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if preset not in PRESETS:
                log.warning("ignoring unknown override strategy %r for %s", preset, domain)
                continue
            override = PRESETS[preset].clone()
            self.overrides.append(
                (
                    domain,
                    override,
                    make_client_hello(
                        override.fake_sni, min_len=max(700, override.seqovl + 200)
                    ),
                    make_fake_client_hello(override.fake_sni),
                )
            )
        self._refresh_thread: threading.Thread | None = None
        self._stats_thread: threading.Thread | None = None
        self._flows: dict[tuple[str, int, str, int], dict[str, object]] = {}
        self._flows_lock = threading.Lock()
        # Flows whose first packets were desynchronised.  Zapret stops after
        # --dpi-desync-cutoff packets; we keep the chosen strategy here so the
        # next few data packets are handled the same way.
        self._desync_flows: dict[tuple[str, int, str, int], dict[str, object]] = {}
        self._desync_lock = threading.Lock()
        # ClientHello reassembly: a large ClientHello is often split across
        # two TCP segments.  We buffer the pieces and desync the complete
        # record, otherwise a DPI sees the SNI in the first segment.
        self._partials: dict[tuple[str, int, str, int], dict[str, object]] = {}
        self._partials_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self.stats = {
            "seen": 0,
            "desynced": 0,
            "data_desynced": 0,
            "reassembled": 0,
            "udp_seen": 0,
            "udp_desynced": 0,
            "voice_desynced": 0,
            "overflow": 0,
            "stall_resets": 0,
        }
        self._t0 = time.time()

    # -- setup --------------------------------------------------------------

    def _needs_sets(self) -> bool:
        return (
            self.general.scope == "list"
            or self.general.block_quic == "list"
            or (self.general.quic == "desync" and bool(self.force_tcp))
        )

    def _resolve(self) -> tuple[list[str], list[str], list[str], list[str]]:
        started = time.time()
        v4, v6 = self.hosts.resolve(self.resolver)
        force4: list[str] = []
        force6: list[str] = []
        if len(self.force_tcp):
            force4, force6 = self.force_tcp.resolve(self.resolver)
        log.info(
            "resolved %d domains -> %d IPv4 / %d IPv6; "
            "force-TCP QUIC %d domains -> %d IPv4 / %d IPv6 in %.1fs",
            len(self.hosts),
            len(v4),
            len(v6),
            len(self.force_tcp),
            len(force4),
            len(force6),
            time.time() - started,
        )
        return v4, v6, force4, force6

    def setup(self) -> None:
        if os.geteuid() != 0:
            raise RuntimeError("Nadejda needs root (CAP_NET_ADMIN + CAP_NET_RAW)")

        # Remove leftovers from a previous run first: they may redirect DNS to
        # a proxy that is not running yet.
        self.firewall.remove(quiet=True)

        v4: list[str] = []
        v6: list[str] = []
        force4: list[str] = []
        force6: list[str] = []
        if self._needs_sets():
            try:
                v4, v6, force4, force6 = self._resolve()
            except Exception as exc:  # noqa: BLE001
                log.error("initial hostlist resolution failed: %s", exc)

        self.sender.start()

        if self.general.dns:
            self.dns = DNSServer(
                self.resolver,
                port=self.general.dns_port,
                strip_aaaa=self.general.dns_strip_aaaa,
                cache_ttl=self.general.dns_cache_ttl,
            )
            self.dns.start()

        self.queue.open()
        self.queue.bind()
        self.firewall.apply()
        if self._needs_sets():
            self.firewall.update_sets(v4, v6, force4, force6)

        try:
            killed = self._kill_stuck_at_startup()
        except Exception as exc:  # noqa: BLE001
            log.debug("startup cleanup failed: %s", exc)
            killed = 0
        if killed:
            log.info("startup cleanup: reset %d stalled TCP connection(s)", killed)

        if self._needs_sets():
            self._refresh_thread = threading.Thread(target=self._refresh_loop, name="hostlist", daemon=True)
            self._refresh_thread.start()
        self._stats_thread = threading.Thread(target=self._stats_loop, name="stats", daemon=True)
        self._stats_thread.start()
        log.info(
            "engine ready: strategy=%s udp=%s ports=%s queue=%d scope=%s quic=%s dns=%s hosts=%d",
            self.strategy.name,
            self.udp_strategy.name,
            ",".join(str(port) for port in self.general.tcp_ports),
            self.general.queue_num,
            self.general.scope,
            self.general.quic,
            self.general.dns,
            len(self.hosts),
        )

    def _refresh_loop(self) -> None:
        interval = max(120, self.general.refresh_seconds)
        while not self.stop_event.wait(interval):
            try:
                v4, v6, force4, force6 = self._resolve()
                self.firewall.update_sets(v4, v6, force4, force6)
            except Exception as exc:  # noqa: BLE001
                log.warning("hostlist refresh failed: %s", exc)

    def _stats_loop(self) -> None:
        while not self.stop_event.wait(60):
            with self._counter_lock:
                stats = dict(self.stats)
            with self._flows_lock:
                cutoff = time.monotonic() - FLOW_TTL
                stale = [key for key, state in self._flows.items() if state["seen"] < cutoff]
                for key in stale:
                    del self._flows[key]
            with self._desync_lock:
                cutoff = time.monotonic() - FLOW_TTL
                stale = [
                    key
                    for key, state in self._desync_flows.items()
                    if state["seen"] < cutoff
                ]
                for key in stale:
                    del self._desync_flows[key]
            with self._partials_lock:
                cutoff = time.monotonic() - FLOW_TTL
                stale = [
                    key
                    for key, state in self._partials.items()
                    if state["seen"] < cutoff
                ]
                for key in stale:
                    del self._partials[key]
            log.info(
                "stats: seen=%d desynced=%d data=%d reasm=%d quic_seen=%d quic_desynced=%d "
                "voice=%d overflow=%d stall_resets=%d sent=%d failed=%d uptime=%ds",
                stats["seen"],
                stats["desynced"],
                stats["data_desynced"],
                stats["reassembled"],
                stats["udp_seen"],
                stats["udp_desynced"],
                stats["voice_desynced"],
                stats["overflow"],
                stats["stall_resets"],
                self.sender.sent,
                self.sender.failed,
                int(time.time() - self._t0),
            )

    # -- packet handling ----------------------------------------------------

    def handle(self, data: bytes) -> int:
        with self._counter_lock:
            self.stats["seen"] += 1
        pkt = parse_packet(data)
        if pkt is not None:
            return self._handle_tcp(pkt)
        udp = parse_udp_packet(data)
        if udp is not None:
            return self._handle_udp(udp)
        return NF_ACCEPT

    def _handle_tcp(self, pkt: Packet) -> int:
        if not pkt.payload or not self._tcp_enabled(pkt.dport):
            return NF_ACCEPT
        hello = parse_client_hello(pkt.payload)
        if self._check_stall(pkt, hello):
            return NF_DROP

        # A flow that we are reassembling gets the next segment appended,
        # even when that segment does not start with a TLS header.
        if self._has_partial(pkt):
            return self._append_partial(pkt)

        # A large ClientHello is often split across TCP segments.  Buffer the
        # pieces and desync the complete record; a fragment alone would either
        # leak the SNI or, if dropped, corrupt the stream.
        record_len = _tls_record_len(pkt.payload)
        if record_len is not None and len(pkt.payload) < record_len:
            return self._start_partial(pkt, record_len, hello)

        if hello is not None:
            return self._desync_hello(pkt, hello)

        # A non-ClientHello packet: either a later data packet of a flow we
        # already desynchronised, or the first request on HTTP / a game port.
        state = self._desync_state(pkt)
        if state is None:
            return NF_ACCEPT
        strategy = state["strategy"]
        data_strategy: Strategy = strategy.clone(positions="1")
        if strategy.frag and strategy.positions == "none":
            return NF_ACCEPT
        if int(state["count"]) >= max(1, int(strategy.cutoff)):
            self._forget_flow(pkt)
            return NF_ACCEPT
        # Desynchronise at most the first data packet of the flow, and only
        # when the seqovl pattern is guaranteed to cover bytes the peer has
        # already acknowledged.  Otherwise the pattern could overwrite bytes
        # that are still in flight and inject garbage into the TLS stream
        # (the server answers with "record overflow").
        if int(state.get("data", 0)) > 0:
            return NF_ACCEPT
        hello_end = state.get("hello_end")
        if hello_end is not None:
            offset = (pkt.seq - int(state["first_seq"])) & 0xFFFFFFFF
            hello_len = (int(hello_end) - int(state["first_seq"])) & 0xFFFFFFFF
            # Only the packet that starts exactly at the end of the hello,
            # and only when the whole overlap fits inside the hello, which
            # the peer has necessarily acknowledged before the handshake
            # could continue.
            if offset != hello_len or strategy.seqovl > hello_len:
                return NF_ACCEPT
        plan = build_plan(
            pkt,
            None,
            data_strategy,
            state["decoy"],  # type: ignore[arg-type]
            state["fake_decoy"],  # type: ignore[arg-type]
        )
        if not plan:
            return NF_ACCEPT
        if not self.sender.submit(plan):
            with self._counter_lock:
                self.stats["overflow"] += 1
            return NF_ACCEPT
        state["count"] = int(state["count"]) + 1
        state["data"] = int(state.get("data", 0)) + 1
        with self._counter_lock:
            self.stats["data_desynced"] += 1
        return NF_DROP

    def _desync_hello(self, pkt: Packet, hello) -> int:
        if not self._should_desync(hello):
            return NF_ACCEPT
        strategy, decoy, fake_decoy = self._select_strategy(hello.sni)
        plan = build_plan(pkt, hello, strategy, decoy, fake_decoy)
        if not plan:
            return NF_ACCEPT
        if not self.sender.submit(plan):
            with self._counter_lock:
                self.stats["overflow"] += 1
            return NF_ACCEPT
        self._remember_flow(pkt, strategy, decoy, fake_decoy, hello.sni)
        with self._counter_lock:
            self.stats["desynced"] += 1
        log.debug(
            "desync %s:%d -> %s:%d sni=%s strategy=%s",
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            hello.sni,
            strategy.name,
        )
        return NF_DROP

    # -- segmented ClientHello --------------------------------------------

    def _has_partial(self, pkt: Packet) -> bool:
        with self._partials_lock:
            return pkt.flow in self._partials

    def _should_desync(self, hello) -> bool:
        """Whether the selected strategy may touch this ClientHello."""
        if self.general.sni_filter:
            if hello.sni is None:
                if not self.general.desync_unknown:
                    return False
            elif not self.hosts.matches(hello.sni):
                return False
        if hello.sni and self.excluded.matches(hello.sni):
            return False
        return True

    def _start_partial(self, pkt: Packet, record_len: int, hello) -> int:
        """Begin buffering a ClientHello that did not fit into one segment.

        The SNI extension is not always inside the first TCP segment: Chromium
        (BoringSSL) places its large post-quantum key share before
        ``server_name``, so the SNI can start well beyond the first MSS.  We
        cannot tell whether the host is listed until the record is complete,
        so every segmented ClientHello is buffered and the decision is made at
        the end.  Unlisted hosts are re-injected unchanged, byte for byte.
        """
        if not looks_like_client_hello(pkt.payload):
            return NF_ACCEPT
        if hello is not None and hello.sni:
            # SNI is already visible: unlisted traffic can pass through
            # immediately instead of being buffered and re-injected.
            if self.general.sni_filter and not self.hosts.matches(hello.sni):
                return NF_ACCEPT
            if self.excluded.matches(hello.sni):
                return NF_ACCEPT
        if not self.sender.available(pkt.version):
            return NF_ACCEPT
        now = time.monotonic()
        with self._partials_lock:
            self._partials[pkt.flow] = {
                "buf": bytearray(pkt.payload),
                "first_seq": pkt.seq,
                "next": (pkt.seq + len(pkt.payload)) & 0xFFFFFFFF,
                "expected": record_len,
                "seg_size": max(1, len(pkt.payload)),
                "sni": hello.sni if hello is not None else None,
                "seen": now,
            }
        log.debug(
            "reassembling ClientHello %s:%d -> %s:%d sni=%s (%d/%d bytes)",
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            hello.sni if hello is not None else None,
            len(pkt.payload),
            record_len,
        )
        return NF_DROP

    def _append_partial(self, pkt: Packet) -> int:
        data = b""
        extra = b""
        first_seq = 0
        seg_size = 1
        with self._partials_lock:
            state = self._partials.get(pkt.flow)
            if state is None:
                return NF_ACCEPT
            state["seen"] = time.monotonic()
            delta = _signed_delta(pkt.seq, int(state["next"]))
            if delta < 0:
                # Retransmission (or an overlap): skip bytes we already have.
                skip = -delta
                if skip >= len(pkt.payload):
                    return NF_DROP
                chunk = pkt.payload[skip:]
            elif delta > 0:
                # A hole appeared.  The buffered prefix was already dropped,
                # so the stream is unusable; reset the flow and let the
                # application reconnect instead of waiting for a timeout.
                del self._partials[pkt.flow]
                state = None
                chunk = b""
            else:
                chunk = pkt.payload
            if state is not None:
                state["buf"].extend(chunk)
                state["next"] = (int(state["next"]) + len(chunk)) & 0xFFFFFFFF
                if len(state["buf"]) < int(state["expected"]):
                    return NF_DROP
                expected = int(state["expected"])
                full = bytes(state["buf"])
                data = full[:expected]
                extra = full[expected:]
                first_seq = int(state["first_seq"])
                seg_size = int(state.get("seg_size", max(1, len(data))))
                del self._partials[pkt.flow]
        if not data:
            self._abort_partial(pkt)
            return NF_DROP
        hello = parse_client_hello(data)
        if hello is None or not self._should_desync(hello):
            # Not ours (or not a ClientHello after all): deliver the original
            # bytes unchanged.  The kernel's own copy was dropped, so without
            # this the connection would stall and retransmit forever.
            self._reinject_partial(pkt, data + extra, first_seq, seg_size)
            return NF_DROP
        synthetic = replace(pkt, payload=data, seq=first_seq)
        log.debug(
            "reassembled ClientHello %s:%d -> %s:%d sni=%s (%d bytes)",
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            hello.sni,
            len(data),
        )
        verdict = self._desync_hello(synthetic, hello)
        if verdict == NF_DROP and extra:
            # The last segment carried more than the ClientHello; forward the
            # remainder so no application data is lost.
            self._send_data(pkt, (first_seq + len(data)) & 0xFFFFFFFF, extra, seg_size)
        return verdict

    def _reinject_partial(
        self, pkt: Packet, data: bytes, first_seq: int, seg_size: int
    ) -> None:
        """Send a buffered ClientHello unchanged (host is not desynced)."""
        if self._send_data(pkt, first_seq, data, seg_size):
            with self._counter_lock:
                self.stats["reassembled"] += 1

    def _send_data(self, pkt: Packet, seq: int, data: bytes, seg_size: int) -> bool:
        if not data:
            return False
        synthetic = replace(pkt, payload=data, seq=seq)
        pieces = split_payload(synthetic, data, [], max(1, seg_size))
        flags = (synthetic.flags | TCP_PSH | TCP_ACK) & 0xFF
        packets = [
            build_segment(synthetic, piece_seq, chunk, flags=flags, ttl=synthetic.ttl)
            for piece_seq, chunk in pieces
        ]
        if not packets:
            return False
        return self.sender.submit([Step(0.0, packets)])

    def _abort_partial(self, pkt: Packet) -> None:
        if self.sender.submit([Step(0.0, [build_reset(pkt)])]):
            with self._counter_lock:
                self.stats["stall_resets"] += 1

    def _tcp_enabled(self, port: int) -> bool:
        if port in self.general.tcp_ports:
            return True
        return self._game_tcp(port)

    def _game_tcp(self, port: int) -> bool:
        return self.general.game_filter in ("tcp", "all") and port_in_ranges(
            port, [self.general.game_tcp_ports]
        )

    def _remember_flow(
        self,
        pkt: Packet,
        strategy: Strategy,
        decoy: bytes,
        fake_decoy: bytes | None,
        sni: str | None,
    ) -> None:
        if int(strategy.cutoff) <= 1:
            return
        with self._desync_lock:
            self._desync_flows[pkt.flow] = {
                "strategy": strategy,
                "decoy": decoy,
                "fake_decoy": fake_decoy,
                "first_seq": pkt.seq,
                "count": 1,
                "data": 0,
                "hello_end": (pkt.seq + len(pkt.payload)) & 0xFFFFFFFF,
                "sni": sni,
                "seen": time.monotonic(),
            }

    def _desync_state(self, pkt: Packet) -> dict[str, object] | None:
        with self._desync_lock:
            state = self._desync_flows.get(pkt.flow)
            if state is not None:
                state["seen"] = time.monotonic()
                return state
        # HTTP and game traffic has no ClientHello.  Start the same state
        # machine on the first request-like packet.
        if pkt.dport == 80 and not _looks_like_http(pkt.payload):
            return None
        if not (pkt.dport == 80 or self._game_tcp(pkt.dport)):
            return None
        strategy = self.strategy
        with self._desync_lock:
            state = {
                "strategy": strategy,
                "decoy": self.decoy,
                "fake_decoy": self.fake_decoy,
                "first_seq": pkt.seq,
                "count": 0,
                "data": 0,
                "hello_end": None,
                "sni": None,
                "seen": time.monotonic(),
            }
            self._desync_flows[pkt.flow] = state
            return state

    def _forget_flow(self, pkt: Packet) -> None:
        with self._desync_lock:
            self._desync_flows.pop(pkt.flow, None)

    def _check_stall(self, pkt: Packet, hello) -> bool:
        """Abort a flow the provider has silently black-holed.

        The provider may drop every packet of a flow right after the
        ClientHello (the server never ACKs any data) or in the middle of a
        response.  The client then retransmits the same bytes with an
        exponential backoff and can hang for 15 minutes.  We detect those
        exact retransmissions and reset the socket, so the application opens
        a new connection immediately and gets a fresh chance to pass the DPI.
        """
        if not self.general.stall_reset:
            return False

        if hello is not None:
            if self.general.sni_filter:
                if hello.sni is None:
                    if not self.general.desync_unknown:
                        return False
                elif not self.hosts.matches(hello.sni):
                    return False
            sni = hello.sni
        else:
            sni = None

        key = pkt.flow
        now = time.monotonic()
        signature = (pkt.seq, len(pkt.payload), hash(pkt.payload))
        reset = False

        with self._flows_lock:
            state = self._flows.get(key)
            if state is None:
                if hello is None:
                    # Not a flow we started guarding: the engine may have
                    # been restarted mid-connection, or the host is not in
                    # the list.  Leave it alone.
                    return False
                self._flows[key] = {
                    "sig": signature,
                    "first": now,
                    "count": 1,
                    "sni": sni,
                    "seen": now,
                }
                return False

            if state["sig"] == signature:
                state["count"] = int(state["count"]) + 1
                state["seen"] = now
                if (
                    int(state["count"]) >= STALL_REPEATS
                    and now - float(state["first"]) >= STALL_MIN_AGE
                ):
                    reset = True
                    sni = state.get("sni")  # type: ignore[assignment]
                    del self._flows[key]
            else:
                # New bytes on the flow: either the handshake progressed or a
                # new request started.  Restart the retransmission counter.
                state["sig"] = signature
                state["first"] = now
                state["count"] = 1
                state["seen"] = now
                if sni:
                    state["sni"] = sni

        if reset:
            self._reset_stalled(pkt, sni)
        return reset

    def _reset_stalled(self, pkt: Packet, sni: str | None) -> None:
        if not self.sender.submit([Step(0.0, [build_reset(pkt)])]):
            return
        with self._counter_lock:
            self.stats["stall_resets"] += 1
        log.info(
            "stall reset %s:%d -> %s:%d sni=%s",
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            sni or "?",
        )

    @staticmethod
    def _stuck_from_ss(text: str) -> list[tuple[str, int, int]]:
        """Pick dead sockets out of ``ss -tniH`` output.

        Returns ``(remote_ip, local_port, remote_port)`` tuples.  Only flows
        to 443 where the peer never acknowledged anything beyond the SYN and
        the client is in retransmission backoff are considered dead.
        """
        sockets: list[tuple[str, int, int]] = []
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if not line.strip() or line[0] in " \t":
                continue
            fields = line.split()
            if len(fields) < 5:
                continue
            try:
                local_port = int(fields[3].rsplit(":", 1)[1])
                remote, remote_port_s = fields[4].rsplit(":", 1)
                remote_port = int(remote_port_s)
            except (IndexError, ValueError):
                continue
            if remote_port != 443:
                continue
            detail = ""
            if index + 1 < len(lines) and lines[index + 1][:1] in (" ", "\t"):
                detail = lines[index + 1]
            values = dict(re.findall(r"(\w+):([0-9]+)(?:/[0-9]+)?", detail))
            try:
                acked = int(values.get("bytes_acked", "-1"))
                backoff = int(values.get("backoff", "0"))
                idle_ms = int(values.get("lastrcv", "0"))
            except ValueError:
                continue
            if acked > 1 or backoff < STUCK_MIN_BACKOFF or idle_ms < STUCK_MIN_IDLE_MS:
                continue
            sockets.append((remote, local_port, remote_port))
        return sockets

    def _kill_stuck_at_startup(self) -> int:
        """Reset connections that were black-holed before Nadejda started.

        Applications do not give up on a TCP connection for many minutes, so
        a socket that got stuck while Nadejda was down keeps the app hanging
        long after the rules are installed.  ``ss`` exposes the kernel's
        accounting (how much the peer acknowledged, retransmission backoff,
        time since the last received packet); dead sockets are destroyed so
        the application reconnects immediately on a fresh 4-tuple.
        """
        ss = shutil.which("ss")
        if not ss:
            return 0
        try:
            proc = subprocess.run(
                [ss, "-tniH"], capture_output=True, text=True, timeout=5
            )
        except (OSError, subprocess.SubprocessError) as exc:
            log.debug("startup cleanup: cannot run ss: %s", exc)
            return 0

        sockets = self._stuck_from_ss(proc.stdout)

        killed = 0
        for remote, local_port, remote_port in sockets:
            try:
                result = subprocess.run(
                    [
                        ss,
                        "-K",
                        "dst",
                        remote,
                        "sport",
                        "=",
                        str(local_port),
                        "dport",
                        "=",
                        str(remote_port),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                log.debug("startup cleanup: ss -K failed: %s", exc)
                continue
            if result.returncode == 0:
                killed += 1
                log.info(
                    "startup cleanup: reset stalled connection :%d -> %s:%d",
                    local_port,
                    remote,
                    remote_port,
                )
            else:
                log.debug(
                    "startup cleanup: cannot reset :%d -> %s:%d: %s",
                    local_port,
                    remote,
                    remote_port,
                    result.stderr.strip(),
                )
        return killed

    def _select_strategy(self, sni: str | None) -> tuple[Strategy, bytes, bytes]:
        host = (sni or "").strip().lower().rstrip(".")
        for domain, strategy, decoy, fake_decoy in self.overrides:
            if host == domain or host.endswith("." + domain):
                return strategy, decoy, fake_decoy
        return self.strategy, self.decoy, self.fake_decoy

    def _handle_udp(self, pkt: UDPPacket) -> int:
        with self._counter_lock:
            self.stats["udp_seen"] += 1
        voice = port_in_ranges(pkt.dport, self.general.udp_voice_ports)
        if self.udp_strategy.mode == "off" and not voice:
            return NF_ACCEPT
        if not voice and pkt.dport == 443:
            # QUIC is controlled by [general] quic; voice ranges are not.
            if self.general.quic != "desync":
                return NF_ACCEPT
        elif not voice:
            return NF_ACCEPT
        if not self.sender.available(pkt.version):
            return NF_ACCEPT

        if voice:
            # Real-time audio/video: send the fakes and the real datagram
            # synchronously, in order.  Returning NF_ACCEPT would let the
            # kernel race the real packet ahead of the raw-socket fakes, and
            # the DPI would then see the real Discord packet first.  Sending
            # everything here avoids both the race and the worker-queue
            # jitter that asynchronous re-injection caused.
            plan = build_udp_plan(
                pkt,
                self.udp_strategy,
                self.general.udp_voice_ports,
            )
            if not plan:
                return NF_ACCEPT
            self.sender.send_now(plan)
            with self._counter_lock:
                self.stats["udp_desynced"] += 1
                self.stats["voice_desynced"] += 1
            log.debug(
                "udp voice %s:%d -> %s:%d bytes=%d fakes=%d",
                pkt.src,
                pkt.sport,
                pkt.dst,
                pkt.dport,
                len(pkt.payload),
                sum(len(step.packets) for step in plan) - 1,
            )
            return NF_DROP

        plan = build_udp_plan(
            pkt, self.udp_strategy, self.general.udp_voice_ports
        )
        if not plan:
            return NF_ACCEPT
        if not self.sender.submit(plan):
            with self._counter_lock:
                self.stats["overflow"] += 1
            return NF_ACCEPT
        with self._counter_lock:
            self.stats["udp_desynced"] += 1
        log.debug(
            "udp desync %s:%d -> %s:%d bytes=%d mode=%s",
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            len(pkt.payload),
            self.udp_strategy.mode,
        )
        return NF_DROP

    # -- lifecycle ----------------------------------------------------------

    def run(self) -> None:
        try:
            self.setup()
            self.queue.run(self.handle, self.stop_event)
        finally:
            self.shutdown()

    def start(self) -> None:
        """Non-blocking variant of :meth:`run` (used by the CLI and tests)."""
        self.setup()
        self._loop_thread = threading.Thread(target=self._loop, name="nfqueue", daemon=True)
        self._loop_thread.start()

    def _loop(self) -> None:
        try:
            self.queue.run(self.handle, self.stop_event)
        except Exception:
            log.exception("queue loop crashed")
        finally:
            if not self.stop_event.is_set():
                log.error("packet loop exited unexpectedly")

    def shutdown(self) -> None:
        self.stop_event.set()
        log.info("shutting down")
        try:
            self.queue.wake()
        except Exception:
            pass
        thread = getattr(self, "_loop_thread", None)
        if thread is not None and thread.is_alive():
            thread.join(timeout=3)
        # Remove the rules before closing the queue: no new packets should be
        # queued while the socket is going away.
        try:
            self.firewall.remove(quiet=True)
        except Exception:
            pass
        try:
            self.queue.close()
        except Exception:
            pass
        if self.dns:
            self.dns.stop()
        self.sender.stop()
        self.resolver.close()
        log.info("stopped")

    def reload_strategy(self, strategy: str | "Strategy") -> None:
        from .desync import PRESETS, Strategy

        if isinstance(strategy, Strategy):
            self.strategy = strategy.clone()
        else:
            if strategy not in PRESETS:
                raise ValueError(f"unknown strategy {strategy}")
            self.strategy = PRESETS[strategy].clone()
        self.decoy = make_client_hello(
            self.strategy.fake_sni, min_len=max(700, self.strategy.seqovl + 200)
        )
        self.fake_decoy = make_fake_client_hello(self.strategy.fake_sni)
        log.info("strategy switched to %s", self.strategy.name)

    def reload_udp_strategy(self, strategy: str | UDPStrategy) -> None:
        from .desync import UDP_PRESETS

        if isinstance(strategy, UDPStrategy):
            self.udp_strategy = strategy.clone()
        else:
            if strategy not in UDP_PRESETS:
                raise ValueError(f"unknown UDP strategy {strategy}")
            self.udp_strategy = UDP_PRESETS[strategy].clone()
        log.info("UDP strategy switched to %s", self.udp_strategy.name)
