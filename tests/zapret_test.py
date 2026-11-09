#!/usr/bin/env python3
"""Zapret-parity tests: profiles, fake payloads, UDP/voice, firewall, engine.

These run as an ordinary user: no nftables, no NFQUEUE and no root.  The
engine is constructed without its raw-socket ``Sender``; every plan that would
be emitted is captured and inspected instead.
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nadejda.config import Config, GeneralConfig  # noqa: E402
from nadejda.desync import (  # noqa: E402
    PRESETS,
    UDP_PRESETS,
    _overlap_pattern,
    build_plan,
    build_udp_plan,
)
from nadejda.engine import Engine  # noqa: E402
from nadejda.firewall import Firewall, FirewallConfig  # noqa: E402
from nadejda.hostlist import HostList  # noqa: E402
from nadejda.nfqueue import NF_ACCEPT, NF_DROP  # noqa: E402
from nadejda.packet import (  # noqa: E402
    checksum,
    make_client_hello,
    make_fake_client_hello,
    parse_client_hello,
    parse_packet,
    parse_udp_packet,
)
from nadejda.payloads import PAYLOADS  # noqa: E402

FAILED = 0
SRC = "192.0.2.10"
DST = "192.0.2.20"


def check(name: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"ok   {name}")
    else:
        FAILED += 1
        print(f"FAIL {name}" + (f": {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# packet builders
# ---------------------------------------------------------------------------


def raw_tcp(payload: bytes, *, sport: int = 40000, dport: int = 443, seq: int = 1000) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 2000, 5 << 4, 0x18, 65535, 0, 0)
    tcp += payload
    pseudo = (
        socket.inet_aton(SRC)
        + socket.inet_aton(DST)
        + struct.pack("!BBH", 0, 6, len(tcp))
    )
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0,
        64,
        6,
        0,
        socket.inet_aton(SRC),
        socket.inet_aton(DST),
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + tcp


def raw_udp(payload: bytes, *, sport: int = 50000, dport: int = 443) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = (
        socket.inet_aton(SRC)
        + socket.inet_aton(DST)
        + struct.pack("!BBH", 0, 17, length)
    )
    csum = checksum(pseudo + header + payload) or 0xFFFF
    header = struct.pack("!HHHH", sport, dport, length, csum)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + length,
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton(SRC),
        socket.inet_aton(DST),
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + header + payload


def tcp_packet(sni: str = "discord.com", **kwargs):
    payload = make_client_hello(sni)
    pkt = parse_packet(raw_tcp(payload, **kwargs))
    assert pkt is not None
    return pkt, parse_client_hello(payload)


def hello_with_late_sni(sni: str, key_share_len: int = 1400) -> bytes:
    """A ClientHello whose SNI extension sits after a large key share.

    Chromium/BoringSSL orders extensions this way once post-quantum key
    exchange is enabled, so the SNI starts beyond the first TCP segment.
    """
    host = sni.encode("ascii")
    sni_list = (
        struct.pack("!H", 3 + len(host)) + b"\x00" + struct.pack("!H", len(host)) + host
    )
    sni_ext = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list
    key_share = struct.pack("!HH", 51, key_share_len) + b"\0" * key_share_len
    exts = key_share + sni_ext
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x04\x13\x01\x13\x02"
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def udp_packet(dport: int, payload: bytes, *, sport: int = 50000):
    pkt = parse_udp_packet(raw_udp(payload, sport=sport, dport=dport))
    assert pkt is not None
    return pkt


def flatten(plan) -> list[bytes]:
    return [raw for step in plan for raw in step.packets]


def reassemble(raws, base: int, size: int, skip_ttl: int | None = None) -> bytes:
    """Reassemble a TCP byte stream the way a peer would (first arrival wins).

    Segments that start before ``base`` are clipped to the receive window,
    exactly like a real TCP stack.  Returns ``size`` bytes; holes stay zero.
    """
    stream: dict[int, int] = {}
    for raw in raws:
        p = parse_packet(raw)
        if p is None or (skip_ttl is not None and p.ttl == skip_ttl):
            continue
        delta = (p.seq - base) & 0xFFFFFFFF
        if delta >= 0x80000000:
            delta -= 0x100000000
        for index, byte in enumerate(p.payload):
            offset = delta + index
            if 0 <= offset < size and offset not in stream:
                stream[offset] = byte
    return bytes(stream.get(index, 0) for index in range(size))


# ---------------------------------------------------------------------------
# fake sender / engine
# ---------------------------------------------------------------------------


class FakeSender:
    def __init__(self) -> None:
        self.plans: list[list[bytes]] = []

    def available(self, version: int) -> bool:  # noqa: ARG002
        return True

    def submit(self, plan) -> bool:
        self.plans.append(flatten(plan))
        return True

    def send_now(self, plan) -> bool:
        self.plans.append(flatten(plan))
        return True


def make_engine(
    *,
    strategy: str = "zapret_general",
    udp: str = "zapret_quic",
    quic: str = "desync",
    sni_filter: bool = True,
    overrides: dict[str, str] | None = None,
    exclude: list[str] | None = None,
    game_filter: str = "off",
    tcp_cutoff: int = 4,
    cutoff: int | None = None,
) -> Engine:
    general = GeneralConfig(
        queue_num=42,
        scope="all",
        sni_filter=sni_filter,
        quic=quic,
        block_quic="off",
        dns=False,
        stall_reset=False,
        game_filter=game_filter,
        tcp_cutoff=tcp_cutoff,
    )
    cfg = Config(
        general=general,
        strategy=PRESETS[strategy].clone(**({"cutoff": cutoff} if cutoff is not None else {})),
        domains=["discord.com", "youtube.com", "soundcloud.com"],
        path=None,  # type: ignore[arg-type]
        udp=UDP_PRESETS[udp].clone(),
        overrides=overrides or {},
        exclude=exclude or [],
    )
    engine = object.__new__(Engine)
    engine.cfg = cfg
    engine.general = cfg.general
    engine.strategy = cfg.strategy
    engine.udp_strategy = cfg.udp.clone()
    engine.hosts = HostList(cfg.domains)
    engine.excluded = HostList(cfg.exclude)
    engine.decoy = make_client_hello(cfg.strategy.fake_sni, min_len=900)
    engine.fake_decoy = make_fake_client_hello(cfg.strategy.fake_sni)
    engine.overrides = []
    for domain, preset in sorted(
        cfg.overrides.items(), key=lambda item: len(item[0]), reverse=True
    ):
        override = PRESETS[preset].clone()
        engine.overrides.append(
            (
                domain,
                override,
                make_client_hello(override.fake_sni, min_len=max(900, override.seqovl + 200)),
                make_fake_client_hello(override.fake_sni),
            )
        )
    engine.sender = FakeSender()
    engine._flows = {}
    engine._flows_lock = __import__("threading").Lock()
    engine._desync_flows = {}
    engine._desync_lock = __import__("threading").Lock()
    engine._partials = {}
    engine._partials_lock = __import__("threading").Lock()
    engine._counter_lock = __import__("threading").Lock()
    engine.stats = {
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
    return engine


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_profiles() -> None:
    expected = {
        "zapret_general": (1, 568, "tls_4pda", False, False),
        "zapret_google": (1, 681, "tls_google", True, False),
        "zapret_discord": (1, 681, "tls_google", False, False),
        "zapret_fake": (1, 568, "tls_4pda", False, True),
        "zapret_fake_fakedsplit": (1, 568, "tls_4pda", False, True),
    }
    for name, (pos, seqovl, pattern, zero, fake) in expected.items():
        strategy = PRESETS[name]
        check(f"profile {name}: exists", True)
        check(f"profile {name}: split position", strategy.positions == str(pos))
        check(f"profile {name}: seqovl", strategy.seqovl == seqovl)
        check(f"profile {name}: pattern", strategy.seqovl_pattern == pattern)
        check(f"profile {name}: ip_id_zero", strategy.ip_id_zero is zero)
        check(f"profile {name}: fake", strategy.fake is fake)
    check("zapret_fake: repeat is 6", PRESETS["zapret_fake"].repeat == 6)
    check("zapret_quic: fake mode", UDP_PRESETS["zapret_quic"].mode == "fake")
    check("zapret_quic: repeat is 6", UDP_PRESETS["zapret_quic"].repeat == 6)
    check("zapret_quic: payload", UDP_PRESETS["zapret_quic"].fake_payload == "quic_google")
    # The aggressive game profile must still use protocol-correct decoys:
    # QUIC on 443 and Discord voice on the voice ranges.
    game = UDP_PRESETS["zapret_game"]
    check("zapret_game: quic payload", game.fake_payload == "quic_google")
    check("zapret_game: voice payload", game.voice_payload == "discord_udp")
    check("zapret_game: voice repeat is sane", game.voice_repeat <= 3)


def test_payloads() -> None:
    expected = {
        "tls_4pda": 284,
        "tls_google": 681,
        "tls_sferum": 661,
        "stun": 100,
        "stun2": 120,
        "quic_google": 1200,
        "discord_udp": 1200,
        "game_udp": 1250,
    }
    for name, size in expected.items():
        check(f"payload {name}: size", len(PAYLOADS.get(name, b"")) == size)
    check("tls blob: ClientHello header", PAYLOADS["tls_google"][:1] == b"\x16")
    check("quic blob: long header", PAYLOADS["quic_google"][0] & 0xC0 == 0xC0)


def test_overlap_pattern() -> None:
    strategy = PRESETS["zapret_general"].clone()
    pattern = _overlap_pattern(strategy, make_client_hello("ya.ru", min_len=900))
    check("pattern: length matches seqovl", len(pattern) == strategy.seqovl)
    check(
        "pattern: 4PDA blob repeated cyclically",
        pattern[: len(PAYLOADS["tls_4pda"])] == PAYLOADS["tls_4pda"]
        and pattern[len(PAYLOADS["tls_4pda"]) : 2 * len(PAYLOADS["tls_4pda"])]
        == PAYLOADS["tls_4pda"],
    )


def test_tcp_plan() -> None:
    for name in ("zapret_general", "zapret_google", "zapret_fake"):
        strategy = PRESETS[name].clone()
        pkt, hello = tcp_packet()
        plan = build_plan(
            pkt,
            hello,
            strategy,
            make_client_hello("ya.ru", min_len=900),
            make_fake_client_hello("ya.ru"),
        )
        assert plan is not None
        packets = [parse_packet(raw) for raw in flatten(plan)]
        # zapret sends the sequence-overlap segment first; it starts exactly
        # seqovl bytes before the real payload and is filled with the decoy
        # blob followed by the first real byte(s).
        want = (pkt.seq - strategy.seqovl) & 0xFFFFFFFF
        overlap = next(
            (p for p in packets if p is not None and p.seq == want and len(p.payload) > 100),
            None,
        )
        check(f"plan {name}: overlap segment", overlap is not None)
        if overlap is None:
            continue
        prefix = strategy.seqovl
        decoy = make_client_hello("ya.ru", min_len=900)
        check(
            f"plan {name}: overlap prefix is blob",
            overlap.payload[:prefix] == _overlap_pattern(strategy, decoy)[:prefix],
        )
        check(
            f"plan {name}: overlap ends with real head",
            overlap.payload[prefix:] == pkt.payload[: len(overlap.payload) - prefix],
        )
        # Whatever order the segments arrive in, the peer must receive the
        # original ClientHello unchanged (the overlap tail is real data).
        raw = flatten(plan)
        skip = strategy.fake_ttl if strategy.fake else None
        check(
            f"plan {name}: stream intact in order",
            reassemble(raw, pkt.seq, len(pkt.payload), skip) == pkt.payload,
        )
        check(
            f"plan {name}: stream intact reversed",
            reassemble(list(reversed(raw)), pkt.seq, len(pkt.payload), skip) == pkt.payload,
        )
        if strategy.ip_id_zero:
            check(f"plan {name}: ip_id zero", overlap.ip_id == 0)
        else:
            check(f"plan {name}: ip_id normal", overlap.ip_id != 0)

    # The live profile uses the decoy ClientHello as the overlap pattern.
    strategy = PRESETS["fake_seqovl_ttl6"].clone()
    pkt, hello = tcp_packet()
    decoy = make_client_hello("ya.ru", min_len=900)
    plan = build_plan(pkt, hello, strategy, decoy, make_fake_client_hello("ya.ru"))
    assert plan is not None
    raw = flatten(plan)
    check(
        "fake_seqovl_ttl6: stream intact in order",
        reassemble(raw, pkt.seq, len(pkt.payload), strategy.fake_ttl) == pkt.payload,
    )
    check(
        "fake_seqovl_ttl6: stream intact reversed",
        reassemble(list(reversed(raw)), pkt.seq, len(pkt.payload), strategy.fake_ttl)
        == pkt.payload,
    )

    strategy = PRESETS["zapret_fake"].clone()
    pkt, hello = tcp_packet()
    plan = build_plan(pkt, hello, strategy, b"x" * 900, b"y" * 400)
    assert plan is not None
    fakes = [
        parse_packet(raw) for raw in flatten(plan) if parse_packet(raw) and parse_packet(raw).ttl == 3
    ]
    check("fake: 6 repeats", len(fakes) == 6)
    check("fake: zapret tls_google payload", fakes[0].payload == PAYLOADS["tls_google"])
    check("fake: low TTL", fakes[0].ttl == 3)
    # Invalid TCP checksum on the decoy.
    first = next(raw for raw in flatten(plan) if parse_packet(raw) and parse_packet(raw).ttl == 3)
    tcp = first[20:]
    pseudo = first[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
    check("fake: broken checksum", checksum(pseudo + tcp) != 0)


def test_udp_plan() -> None:
    ports = ["19294-19344", "50000-50100"]
    quic = PAYLOADS["quic_google"]

    fake = UDP_PRESETS["zapret_quic"].clone()
    plan = build_udp_plan(udp_packet(443, quic), fake, ports)
    assert plan is not None
    packets = [parse_udp_packet(raw) for raw in flatten(plan)]
    check("udp fake: 6 decoys + real", len(packets) == 7)
    check("udp fake: decoy payload", packets[0].payload == PAYLOADS["quic_google"])
    # Zapret's UDP fakes keep the original TTL and a valid checksum.  A home
    # NAT with nf_conntrack_checksum=1 drops badsum packets before they can
    # reach the DPI, and TTL 3 may expire before an ISP-level DPI.
    check("udp fake: decoy keeps original TTL", packets[0].ttl == 64)
    raw0 = packets[0].raw
    ihl = (raw0[0] & 0x0F) * 4
    udp = raw0[ihl:]
    pseudo = raw0[12:20] + struct.pack("!BBH", 0, 17, len(udp))
    check("udp fake: decoy checksum valid", checksum(pseudo + udp) == 0)
    check("udp fake: real payload intact", packets[-1].payload == quic)
    check("udp fake: real TTL", packets[-1].ttl == 64)

    frag = UDP_PRESETS["quic_frag"].clone()
    plan = build_udp_plan(udp_packet(443, quic), frag, ports)
    assert plan is not None
    raw = flatten(plan)
    check("udp frag: at least two fragments", len(raw) >= 2)
    chunks = {}
    ident = None
    for packet in raw:
        frag_off = struct.unpack("!H", packet[6:8])[0]
        ident = struct.unpack("!H", packet[4:6])[0]
        ihl = (packet[0] & 0x0F) * 4
        chunks[(frag_off & 0x1FFF) * 8] = packet[ihl:]
    check("udp frag: same IP id", ident is not None)
    check(
        "udp frag: reassembles to original",
        b"".join(chunks[k] for k in sorted(chunks))[8:] == quic,
    )

    # Voice must be faked even in fragmentation mode (zapret does this).
    voice_plan = build_udp_plan(udp_packet(50000, b"voice"), frag, ports)
    assert voice_plan is not None
    voice = [parse_udp_packet(raw) for raw in flatten(voice_plan)]
    check("voice: fake added in frag mode", len(voice) == 4)
    check("voice: decoy is discord blob", voice[0].payload == PAYLOADS["discord_udp"])
    voice_raw = voice[0].raw
    voice_ihl = (voice_raw[0] & 0x0F) * 4
    voice_udp = voice_raw[voice_ihl:]
    voice_pseudo = voice_raw[12:20] + struct.pack("!BBH", 0, 17, len(voice_udp))
    check("voice: decoy checksum valid", checksum(voice_pseudo + voice_udp) == 0)
    check("voice: decoy keeps original TTL", voice[0].ttl == 64)
    check("voice: real datagram preserved", voice[-1].payload == b"voice")
    fakes_only = build_udp_plan(
        udp_packet(50000, b"voice"), frag, ports, fakes_only=True
    )
    assert fakes_only is not None
    only = [parse_udp_packet(raw) for raw in flatten(fakes_only)]
    check("voice: fakes-only omits the real datagram", len(only) == 3)
    check("voice: fakes-only all decoys", all(p.payload == PAYLOADS["discord_udp"] for p in only))

    # TURN/STUN on UDP/443 must not be touched.
    stun = b"\x00\x01\x00\x50" + bytes(96)
    check("stun on 443: untouched", build_udp_plan(udp_packet(443, stun), fake, ports) is None)
    check("voice port outside range: untouched", build_udp_plan(udp_packet(51000, b"x"), frag, ports) is None)

    # Disabling QUIC must not disable Discord voice / screen sharing.
    off = UDP_PRESETS["quic_off"].clone()
    check("udp off: QUIC untouched", build_udp_plan(udp_packet(443, quic), off, ports) is None)
    off_voice = build_udp_plan(udp_packet(50000, b"voice"), off, ports)
    assert off_voice is not None
    check("udp off: voice still faked", len(flatten(off_voice)) == 4)


def test_firewall() -> None:
    base = dict(queue_num=200, mark=0x4E414445, scope="all", quic="desync", dns=False)
    ruleset = Firewall(FirewallConfig(**base)).build_ruleset()
    check("nft: TCP port set", "tcp dport { 80, 443, 2053, 2083, 2087, 2096, 8443 }" in ruleset)
    check("nft: tcp cutoff counts SYN", "ct original packets <= 16" in ruleset)
    tcp_line = next(
        (line for line in ruleset.splitlines() if "tcp dport { 80" in line), ""
    )
    check("nft: small TCP segments queued", "meta length" not in tcp_line, tcp_line)
    check("nft: voice ranges", "udp dport { 19294-19344, 50000-50100 }" in ruleset)
    voice_line = next(
        (line for line in ruleset.splitlines() if "19294" in line), ""
    )
    check(
        "nft: every voice datagram queued",
        "ct original packets" not in voice_line,
        voice_line,
    )
    check("nft: quic cutoff", "udp dport 443 ct original packets <= 6" in ruleset)
    check("nft: no game ports by default", "game" not in ruleset)
    check("nft: queues to configured queue", "queue num 200 bypass" in ruleset)

    game = Firewall(
        FirewallConfig(**base, game_filter="all", game_tcp_ports="27000-27100", game_udp_ports="27015")
    ).build_ruleset()
    check("nft: game TCP range", "tcp dport 27000-27100" in game)
    check("nft: game UDP range", "udp dport 27015" in game)

    no_cutoff = Firewall(
        FirewallConfig(
            **dict(base, quic="off"),
            tcp_cutoff=0,
            udp_cutoff=0,
            udp_voice_ports=(),
        )
    ).build_ruleset()
    check("nft: quic off leaves UDP/443 alone", "udp dport 443" not in no_cutoff)
    check("nft: empty voice list omitted", "19294" not in no_cutoff)


def test_engine() -> None:
    engine = make_engine()
    pkt, _ = tcp_packet("discord.com", sport=41000)
    verdict = engine._handle_tcp(pkt)
    check("engine: ClientHello desynced", verdict == NF_DROP)
    check("engine: plan submitted", len(engine.sender.plans) == 1)
    check("engine: flow remembered", pkt.flow in engine._desync_flows)

    # Only the first data packet, starting exactly at the end of the hello,
    # is desynchronised.  A later packet is passed through untouched.
    engine = make_engine()
    pkt, _ = tcp_packet("discord.com", sport=41000)
    hello_len = len(pkt.payload)
    engine._handle_tcp(pkt)
    first = parse_packet(raw_tcp(b"A" * 400, sport=41000, seq=pkt.seq + hello_len))
    second = parse_packet(
        raw_tcp(b"B" * 400, sport=41000, seq=pkt.seq + hello_len + 400)
    )
    assert first is not None and second is not None
    check("engine: first data packet desynced", engine._handle_tcp(first) == NF_DROP)
    check("engine: data counter", engine.stats["data_desynced"] == 1)
    check("engine: later data packet accepted", engine._handle_tcp(second) == NF_ACCEPT)
    check("engine: data counter unchanged", engine.stats["data_desynced"] == 1)

    # A data packet whose seqovl would reach outside the acknowledged hello
    # must not be desynchronised (that corrupts the TLS stream).
    engine = make_engine()
    pkt, _ = tcp_packet("discord.com", sport=41100)
    engine._handle_tcp(pkt)
    inside = parse_packet(raw_tcp(b"C" * 400, sport=41100, seq=pkt.seq + 100))
    assert inside is not None
    check("engine: unsafe overlap accepted", engine._handle_tcp(inside) == NF_ACCEPT)
    check("engine: unsafe overlap not counted", engine.stats["data_desynced"] == 0)

    # Excluded SNI is ignored.
    engine = make_engine(exclude=["discord.com"])
    pkt, _ = tcp_packet("discord.com", sport=42000)
    check("engine: excluded host accepted", engine._handle_tcp(pkt) == NF_ACCEPT)
    check("engine: excluded host has no plan", not engine.sender.plans)

    # Override wins for the matching suffix.
    engine = make_engine(overrides={"discord.com": "zapret_google"})
    pkt, _ = tcp_packet("cdn.discord.com", sport=43000)
    engine._handle_tcp(pkt)
    state = engine._desync_flows[pkt.flow]
    check("engine: override used", state["strategy"].name == "zapret_google")

    # Voice UDP is faked even when QUIC mode is off.
    engine = make_engine(quic="off", udp="quic_frag")
    voice = udp_packet(50000, b"voice")
    check("engine: voice desynced with quic off", engine._handle_udp(voice) == NF_DROP)
    check("engine: voice counter", engine.stats["voice_desynced"] == 1)
    check("engine: voice plan has decoy+real", len(engine.sender.plans[-1]) == 4)

    # QUIC is skipped when quic = off.
    engine = make_engine(quic="off", udp="zapret_quic")
    check("engine: quic off accepts UDP/443", engine._handle_udp(udp_packet(443, PAYLOADS["quic_google"])) == NF_ACCEPT)

    # Even with the quic_off UDP strategy, voice keeps its fake.
    engine = make_engine(quic="off", udp="quic_off")
    check("engine: voice desynced with udp off", engine._handle_udp(udp_packet(50000, b"voice")) == NF_DROP)
    check("engine: voice counter with udp off", engine.stats["voice_desynced"] == 1)
    check("engine: udp off accepts UDP/443", engine._handle_udp(udp_packet(443, PAYLOADS["quic_google"])) == NF_ACCEPT)

    # Cutoff=1 means the hello is not even remembered, so later packets are
    # never touched.
    engine = make_engine(cutoff=1)
    pkt, _ = tcp_packet("discord.com", sport=44000)
    check("engine: hello desynced", engine._handle_tcp(pkt) == NF_DROP)
    check("engine: cutoff=1 forgets flow", pkt.flow not in engine._desync_flows)
    after = parse_packet(raw_tcp(b"B" * 400, sport=44000, seq=pkt.seq + 1000))
    assert after is not None
    check("engine: packet after cutoff accepted", engine._handle_tcp(after) == NF_ACCEPT)

    # A ClientHello split across TCP segments is reassembled, then desynced
    # as one complete record.
    engine = make_engine()
    big = make_client_hello("discord.com")
    cut = 1448
    first = parse_packet(raw_tcp(big[:cut], sport=46000, seq=5000))
    second = parse_packet(raw_tcp(big[cut:], sport=46000, seq=5000 + cut))
    assert first is not None and second is not None
    check("engine: partial ClientHello buffered", engine._handle_tcp(first) == NF_DROP)
    check("engine: partial not desynced yet", not engine.sender.plans)
    check("engine: tail completes reassembly", engine._handle_tcp(second) == NF_DROP)
    check("engine: reassembled hello desynced", len(engine.sender.plans) == 1)
    check("engine: reassembled flow remembered", first.flow in engine._desync_flows)
    check("engine: partial state cleared", first.flow not in engine._partials)

    # An unlisted host must not be buffered or dropped.
    engine = make_engine()
    other = make_client_hello("example.com")
    third = parse_packet(raw_tcp(other[:cut], sport=46100, seq=6000))
    fourth = parse_packet(raw_tcp(other[cut:], sport=46100, seq=6000 + cut))
    assert third is not None and fourth is not None
    check("engine: unlisted partial accepted", engine._handle_tcp(third) == NF_ACCEPT)
    check("engine: unlisted tail accepted", engine._handle_tcp(fourth) == NF_ACCEPT)
    check("engine: unlisted not desynced", not engine.sender.plans)

    # Chromium (BoringSSL) puts a large post-quantum key share before
    # server_name, so the SNI is not in the first TCP segment.  Such a record
    # must still be buffered and desynchronised after reassembly.
    engine = make_engine()
    late = hello_with_late_sni("discord.com")
    first = parse_packet(raw_tcp(late[:1388], sport=46200, seq=7000))
    second = parse_packet(raw_tcp(late[1388:], sport=46200, seq=7000 + 1388))
    assert first is not None and second is not None
    check("engine: late-SNI partial buffered", engine._handle_tcp(first) == NF_DROP)
    check("engine: late-SNI tail desyncs", engine._handle_tcp(second) == NF_DROP)
    check("engine: late-SNI plan submitted", len(engine.sender.plans) == 1)
    check("engine: late-SNI flow remembered", first.flow in engine._desync_flows)
    if engine.sender.plans:
        stream = reassemble(engine.sender.plans[-1], 7000, len(late))
        check("engine: late-SNI stream intact", stream == late)

    # An unlisted host with a late SNI is buffered (the SNI cannot be checked
    # earlier) but then re-injected byte for byte instead of being desynced.
    engine = make_engine()
    late = hello_with_late_sni("example.com")
    first = parse_packet(raw_tcp(late[:1388], sport=46210, seq=7100))
    second = parse_packet(raw_tcp(late[1388:], sport=46210, seq=7100 + 1388))
    assert first is not None and second is not None
    check("engine: late-SNI unlisted buffered", engine._handle_tcp(first) == NF_DROP)
    check("engine: late-SNI unlisted tail reinjected", engine._handle_tcp(second) == NF_DROP)
    check("engine: late-SNI unlisted not desynced", not engine._desync_flows)
    check("engine: late-SNI reasm counter", engine.stats["reassembled"] == 1)
    if engine.sender.plans:
        stream = reassemble(engine.sender.plans[-1], 7100, len(late))
        check("engine: late-SNI unlisted bytes intact", stream == late)

    # Game filter opens the port range only when enabled.
    engine = make_engine(game_filter="off")
    game = parse_packet(raw_tcp(b"PING" * 10, sport=45000, dport=27015))
    assert game is not None
    check("engine: game port ignored when filter off", not engine._tcp_enabled(27015))
    engine = make_engine(game_filter="tcp")
    check("engine: game port enabled with tcp filter", engine._tcp_enabled(27015))
    check("engine: port below game range", not engine._game_tcp(80))


def main() -> int:
    test_profiles()
    test_payloads()
    test_overlap_pattern()
    test_tcp_plan()
    test_udp_plan()
    test_firewall()
    test_engine()
    if FAILED:
        print(f"\n{FAILED} check(s) failed")
        return 1
    print("\nzapret tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
