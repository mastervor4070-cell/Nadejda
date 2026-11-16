"""The Windows engine: WinDivert + the portable desync planner.

This is the Windows counterpart of :mod:`nadejda.engine`.  It keeps the same
per-flow state machine (ClientHello reassembly, ``cutoff``, per-domain
overrides, QUIC fragmentation, Discord voice fakes), but packets are captured
and injected with WinDivert instead of nftables/NFQUEUE/raw sockets.

``process()`` is deliberately free of any Windows API: it takes one raw IP
packet and returns a :class:`Decision`.  That makes the whole strategy layer
testable on Linux with a fake handle (see ``tests/win_engine_test.py``).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..config import Config
from ..desync import (
    PRESETS,
    Step,
    Strategy,
    UDPStrategy,
    build_plan,
    build_udp_plan,
    port_in_ranges,
)
from ..hostlist import HostList
from ..packet import (
    TCP_ACK,
    TCP_PSH,
    Packet,
    UDPPacket,
    build_segment,
    looks_like_client_hello,
    make_client_hello,
    make_fake_client_hello,
    parse_client_hello,
    parse_packet,
    parse_udp_packet,
    split_payload,
)

log = logging.getLogger(__name__)

# Same value as the Linux engine: state for a flow that has been idle this
# long is discarded.
FLOW_TTL = 180.0
STATUS_INTERVAL = 2.0

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


@dataclass(slots=True)
class Decision:
    """What to do with a captured packet.

    ``drop`` means "the original packet must not continue through the stack";
    ``steps`` are the packets to inject instead (empty means a deliberate black
    hole, e.g. QUIC in ``block`` mode).  ``drop=False`` re-injects the original
    packet unchanged.
    """

    drop: bool = False
    steps: list[Step] = field(default_factory=list)

    @property
    def packets(self) -> list[bytes]:
        return [raw for step in self.steps for raw in step.packets]


# ---------------------------------------------------------------------------
# WinDivert filter
# ---------------------------------------------------------------------------


def _port_terms(prefix: str, ports) -> list[str]:
    terms: list[str] = []
    for port in ports or ():
        try:
            terms.append(f"{prefix}.DstPort == {int(port)}")
        except (TypeError, ValueError):
            continue
    return terms


def _range_terms(prefix: str, ranges) -> list[str]:
    terms: list[str] = []
    for item in ranges or ():
        text = str(item).strip()
        if not text:
            continue
        try:
            if "-" in text:
                low, high = text.split("-", 1)
                terms.append(
                    f"({prefix}.DstPort >= {int(low)} and "
                    f"{prefix}.DstPort <= {int(high)})"
                )
            else:
                terms.append(f"{prefix}.DstPort == {int(text)}")
        except ValueError:
            continue
    return terms


def build_filter(cfg: Config) -> str:
    """Build the WinDivert filter for the configured ports.

    Only outbound packets that carry a payload are intercepted.  Pure ACKs and
    handshake packets are left alone; everything we do not rewrite is injected
    back unchanged by the engine loop.
    """
    general = cfg.general
    groups: list[str] = []

    tcp = _port_terms("tcp", general.tcp_ports)
    if general.game_filter in ("tcp", "all"):
        tcp += _range_terms("tcp", [general.game_tcp_ports])
    if tcp:
        groups.append("(" + " or ".join(tcp) + ") and tcp.PayloadLength > 0")

    udp: list[str] = []
    if general.quic != "off":
        udp.append("udp.DstPort == 443")
    udp += _range_terms("udp", general.udp_voice_ports)
    if general.game_filter in ("udp", "all"):
        udp += _range_terms("udp", [general.game_udp_ports])
    if udp:
        groups.append("(" + " or ".join(udp) + ") and udp.PayloadLength > 0")

    if not groups:
        return "false"
    return "outbound and not loopback and (" + " or ".join(groups) + ")"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class WinEngine:
    def __init__(self, cfg: Config, handle=None, status_path: str | Path | None = None):
        self.cfg = cfg
        self.general = cfg.general
        self.strategy: Strategy = cfg.strategy.clone()
        self.udp_strategy: UDPStrategy = cfg.udp.clone()
        self.hosts = HostList(cfg.domains)
        self.excluded = HostList(cfg.exclude)
        self.handle = handle
        self.status_path = Path(status_path) if status_path else None
        self.stop_event = threading.Event()

        self.decoy = make_client_hello(
            self.strategy.fake_sni, min_len=max(700, self.strategy.seqovl + 200)
        )
        self.fake_decoy = make_fake_client_hello(self.strategy.fake_sni)

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

        self._flows_lock = threading.Lock()
        self._desync_flows: dict[tuple[str, int, str, int], dict[str, object]] = {}
        self._partials: dict[tuple[str, int, str, int], dict[str, object]] = {}
        self._stats_lock = threading.Lock()
        self.stats = {
            "seen": 0,
            "desynced": 0,
            "data_desynced": 0,
            "reassembled": 0,
            "udp_seen": 0,
            "udp_desynced": 0,
            "voice_desynced": 0,
            "dropped": 0,
            "injected": 0,
            "passed": 0,
            "errors": 0,
            "partial_aborts": 0,
        }
        self.filter = build_filter(cfg)
        self._started_at = time.time()
        self._last_status = 0.0
        self._last_prune = time.monotonic()

    # -- lifecycle ----------------------------------------------------------

    def run(self) -> None:
        """Capture/inject until :meth:`stop` is called."""
        handle = self.handle
        if handle is None:
            from .divert import WinDivertHandle

            handle = WinDivertHandle(self.filter)
            self.handle = handle
        if not getattr(handle, "is_open", False):
            handle.open()
        self._started_at = time.time()
        log.info("Nadejda for Windows started; filter = %s", self.filter)
        try:
            while not self.stop_event.is_set():
                try:
                    captured = handle.recv(timeout=0.5)
                except TimeoutError:
                    captured = None
                except Exception as exc:  # WinDivert errors are OSError/WindowsError
                    if self.stop_event.is_set():
                        break
                    with self._stats_lock:
                        self.stats["errors"] += 1
                    log.error("WinDivert receive failed: %s", exc)
                    time.sleep(0.5)
                    continue
                if captured is None:
                    self._prune()
                    self._write_status()
                    continue
                self.handle_captured(captured)
                self._prune()
                self._write_status()
        finally:
            try:
                handle.close()
            except Exception:
                pass
            self._write_status(final=True)
            log.info("Nadejda for Windows stopped")

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self.run, name="windivert", daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        self.stop_event.set()

    # -- one packet ---------------------------------------------------------

    def handle_captured(self, captured) -> None:
        with self._stats_lock:
            self.stats["seen"] += 1
        try:
            decision = self.process(captured.raw)
        except Exception:
            log.exception("packet processing failed; passing the packet through")
            decision = Decision()

        interface = getattr(captured, "interface", None)
        if decision.drop:
            self._emit(decision, interface)
            with self._stats_lock:
                self.stats["dropped"] += 1
        else:
            # Pass the packet through with its own checksum flags: the NIC may
            # not have computed them yet (offload), and re-injecting with the
            # flags cleared would send a zero checksum.
            checksums = (
                bool(getattr(captured, "ip_checksum", False)),
                bool(getattr(captured, "tcp_checksum", False)),
                bool(getattr(captured, "udp_checksum", False)),
            )
            self._send(captured.raw, interface, checksums)
            with self._stats_lock:
                self.stats["passed"] += 1

    def _emit(self, decision: Decision, interface=None) -> None:
        for step in decision.steps:
            if step.delay_ms:
                time.sleep(step.delay_ms / 1000.0)
            for raw in step.packets:
                # Engine-built packets carry final checksums, including the
                # deliberately broken ones of fake_badsum decoys.
                self._send(raw, interface)

    def _send(
        self,
        raw: bytes,
        interface=None,
        checksums: tuple[bool, bool, bool] | None = None,
    ) -> None:
        handle = self.handle
        if handle is None:
            raise RuntimeError("engine has no divert handle")
        try:
            if checksums is None:
                handle.send(raw, interface)
            else:
                handle.send(raw, interface, checksums)
        except Exception as exc:
            with self._stats_lock:
                self.stats["errors"] += 1
            log.debug("inject failed: %s", exc)
            return
        with self._stats_lock:
            self.stats["injected"] += 1

    def process(self, raw: bytes) -> Decision:
        """Decide what to do with one outbound IP packet."""
        pkt = parse_packet(raw)
        if pkt is not None:
            return self._handle_tcp(pkt)
        udp = parse_udp_packet(raw)
        if udp is not None:
            return self._handle_udp(udp)
        return Decision()

    # -- TCP ----------------------------------------------------------------

    def _handle_tcp(self, pkt: Packet) -> Decision:
        if not pkt.payload or not self._tcp_enabled(pkt.dport):
            return Decision()
        hello = parse_client_hello(pkt.payload)

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
            return Decision()
        strategy: Strategy = state["strategy"]  # type: ignore[assignment]
        data_strategy: Strategy = strategy.clone(positions="1")
        if strategy.frag and strategy.positions == "none":
            return Decision()
        if int(state["count"]) >= max(1, int(strategy.cutoff)):
            self._forget_flow(pkt)
            return Decision()
        # Desynchronise at most the first data packet of the flow, and only
        # when the seqovl pattern is guaranteed to cover bytes the peer has
        # already acknowledged.
        if int(state.get("data", 0)) > 0:
            return Decision()
        hello_end = state.get("hello_end")
        if hello_end is not None:
            offset = (pkt.seq - int(state["first_seq"])) & 0xFFFFFFFF
            hello_len = (int(hello_end) - int(state["first_seq"])) & 0xFFFFFFFF
            if offset != hello_len or strategy.seqovl > hello_len:
                return Decision()
        plan = build_plan(
            pkt,
            None,
            data_strategy,
            state["decoy"],  # type: ignore[arg-type]
            state["fake_decoy"],  # type: ignore[arg-type]
        )
        if not plan:
            return Decision()
        state["count"] = int(state["count"]) + 1
        state["data"] = int(state.get("data", 0)) + 1
        with self._stats_lock:
            self.stats["data_desynced"] += 1
        log.debug(
            "data desync %s:%d -> %s:%d strategy=%s",
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            strategy.name,
        )
        return Decision(True, plan)

    def _desync_hello(self, pkt: Packet, hello) -> Decision:
        if not self._should_desync(hello):
            return Decision()
        strategy, decoy, fake_decoy = self._select_strategy(hello.sni)
        plan = build_plan(pkt, hello, strategy, decoy, fake_decoy)
        if not plan:
            return Decision()
        self._remember_flow(pkt, strategy, decoy, fake_decoy, hello.sni)
        with self._stats_lock:
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
        return Decision(True, plan)

    # -- segmented ClientHello ---------------------------------------------

    def _has_partial(self, pkt: Packet) -> bool:
        with self._flows_lock:
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

    def _start_partial(self, pkt: Packet, record_len: int, hello) -> Decision:
        """Begin buffering a ClientHello that did not fit into one segment.

        Chromium (BoringSSL) places a large post-quantum key share before
        ``server_name``, so the SNI can start well beyond the first MSS.  We
        cannot tell whether the host is listed until the record is complete, so
        every segmented ClientHello is buffered and the decision is made at the
        end.  Unlisted hosts are re-injected unchanged, byte for byte.
        """
        if not looks_like_client_hello(pkt.payload):
            return Decision()
        if hello is not None and hello.sni:
            if self.general.sni_filter and not self.hosts.matches(hello.sni):
                return Decision()
            if self.excluded.matches(hello.sni):
                return Decision()
        now = time.monotonic()
        with self._flows_lock:
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
        return Decision(True)

    def _append_partial(self, pkt: Packet) -> Decision:
        data = b""
        extra = b""
        first_seq = 0
        seg_size = 1
        with self._flows_lock:
            state = self._partials.get(pkt.flow)
            if state is None:
                return Decision()
            state["seen"] = time.monotonic()
            delta = _signed_delta(pkt.seq, int(state["next"]))
            if delta < 0:
                # Retransmission (or an overlap): skip bytes we already have.
                skip = -delta
                if skip >= len(pkt.payload):
                    return Decision(True)
                chunk = pkt.payload[skip:]
            elif delta > 0:
                # A hole appeared.  The buffered prefix was already dropped, so
                # the stream is unusable; reset the flow and let the
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
                    return Decision(True)
                expected = int(state["expected"])
                full = bytes(state["buf"])
                data = full[:expected]
                extra = full[expected:]
                first_seq = int(state["first_seq"])
                seg_size = int(state.get("seg_size", max(1, len(data))))
                del self._partials[pkt.flow]
        if not data:
            return self._abort_partial(pkt)
        hello = parse_client_hello(data)
        if hello is None or not self._should_desync(hello):
            # Not ours (or not a ClientHello after all): deliver the original
            # bytes unchanged.  The original segments were dropped, so without
            # this the connection would stall and retransmit forever.
            steps = self._reinject(pkt, data + extra, first_seq, seg_size)
            return Decision(True, steps)
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
        decision = self._desync_hello(synthetic, hello)
        if decision.drop and extra:
            # The last segment carried more than the ClientHello; forward the
            # remainder so no application data is lost.
            decision.steps.extend(
                self._reinject(pkt, extra, (first_seq + len(data)) & 0xFFFFFFFF, seg_size)
            )
        return decision

    def _reinject(self, pkt: Packet, data: bytes, seq: int, seg_size: int) -> list[Step]:
        """Packets that deliver ``data`` unchanged at ``seq``."""
        if not data:
            return []
        synthetic = replace(pkt, payload=data, seq=seq)
        pieces = split_payload(synthetic, data, [], max(1, seg_size))
        flags = (synthetic.flags | TCP_PSH | TCP_ACK) & 0xFF
        packets = [
            build_segment(synthetic, piece_seq, chunk, flags=flags, ttl=synthetic.ttl)
            for piece_seq, chunk in pieces
        ]
        if not packets:
            return []
        with self._stats_lock:
            self.stats["reassembled"] += 1
        return [Step(0.0, packets)]

    def _abort_partial(self, pkt: Packet) -> Decision:
        """Give up on a buffered record that lost a segment.

        The Linux engine sends a spoofed RST here so the application
        reconnects at once.  A RST travels *inbound* (server -> client), while
        this WinDivert handle injects outbound packets only, so instead the
        buffered flow is dropped and forgotten: the client's TCP stack
        retransmits the unacknowledged bytes, which then pass through
        unchanged.
        """
        with self._stats_lock:
            self.stats["partial_aborts"] += 1
        return Decision(True)

    # -- per-flow state -----------------------------------------------------

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
        with self._flows_lock:
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
        with self._flows_lock:
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
        with self._flows_lock:
            state = {
                "strategy": self.strategy,
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
        with self._flows_lock:
            self._desync_flows.pop(pkt.flow, None)

    def _select_strategy(self, sni: str | None) -> tuple[Strategy, bytes, bytes]:
        host = (sni or "").strip().lower().rstrip(".")
        for domain, strategy, decoy, fake_decoy in self.overrides:
            if host == domain or host.endswith("." + domain):
                return strategy, decoy, fake_decoy
        return self.strategy, self.decoy, self.fake_decoy

    # -- UDP ----------------------------------------------------------------

    def _handle_udp(self, pkt: UDPPacket) -> Decision:
        with self._stats_lock:
            self.stats["udp_seen"] += 1
        voice = port_in_ranges(pkt.dport, self.general.udp_voice_ports)
        if self.udp_strategy.mode == "off" and not voice:
            return Decision()
        if not voice and pkt.dport == 443:
            # QUIC is controlled by [general] quic; voice ranges are not.
            if self.general.quic == "block":
                # Silently dropping the datagram makes the browser fall back
                # to TCP, where the regular strategy already works.
                with self._stats_lock:
                    self.stats["udp_desynced"] += 1
                return Decision(True)
            if self.general.quic != "desync":
                return Decision()
        elif not voice:
            return Decision()

        plan = build_udp_plan(pkt, self.udp_strategy, self.general.udp_voice_ports)
        if not plan:
            return Decision()
        with self._stats_lock:
            self.stats["udp_desynced"] += 1
            if voice:
                self.stats["voice_desynced"] += 1
        log.debug(
            "udp %s %s:%d -> %s:%d bytes=%d packets=%d",
            "voice" if voice else "desync",
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            len(pkt.payload),
            sum(len(step.packets) for step in plan),
        )
        return Decision(True, plan)

    # -- housekeeping -------------------------------------------------------

    def _prune(self) -> None:
        now = time.monotonic()
        if now - self._last_prune < 5.0:
            return
        self._last_prune = now
        cutoff = now - FLOW_TTL
        with self._flows_lock:
            for store in (self._desync_flows, self._partials):
                stale = [
                    key
                    for key, state in store.items()
                    if float(state.get("seen", 0.0)) < cutoff
                ]
                for key in stale:
                    store.pop(key, None)

    def stats_snapshot(self) -> dict[str, object]:
        with self._stats_lock:
            stats = dict(self.stats)
        return {
            "pid": os.getpid(),
            "uptime": round(time.time() - self._started_at, 1),
            "filter": self.filter,
            "strategy": self.strategy.name,
            "udp_strategy": self.udp_strategy.name,
            "quic": self.general.quic,
            "running": not self.stop_event.is_set(),
            "stats": stats,
        }

    def _write_status(self, final: bool = False) -> None:
        if self.status_path is None:
            return
        now = time.monotonic()
        if not final and now - self._last_status < STATUS_INTERVAL:
            return
        self._last_status = now
        try:
            payload = self.stats_snapshot()
            payload["final"] = final
            self.status_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.status_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
            os.replace(tmp, self.status_path)
        except OSError as exc:
            log.debug("cannot write status file: %s", exc)

    # -- live changes (used by the GUI) -------------------------------------

    def set_strategy(self, name: str) -> None:
        if name not in PRESETS:
            raise ValueError(f"unknown strategy {name!r}")
        self.strategy = PRESETS[name].clone()
        self.decoy = make_client_hello(
            self.strategy.fake_sni, min_len=max(700, self.strategy.seqovl + 200)
        )
        self.fake_decoy = make_fake_client_hello(self.strategy.fake_sni)
        log.info("strategy switched to %s", name)

    def set_udp_strategy(self, name: str) -> None:
        from ..desync import UDP_PRESETS

        if name not in UDP_PRESETS:
            raise ValueError(f"unknown UDP strategy {name!r}")
        self.udp_strategy = UDP_PRESETS[name].clone()
        log.info("UDP strategy switched to %s", name)
