"""TCP-level DPI desynchronisation strategies.

Each strategy turns one captured ClientHello segment into a plan: a list of
steps, each step being a small delay followed by raw IP packets to emit.

The two workhorses are:

``split``      slice the ClientHello into several TCP segments so a DPI that
               only inspects the first segment never sees the full SNI.

``seqovl``     send the tail of the ClientHello with a sequence-number overlap
               that starts *before* the stream, filled with a decoy ClientHello
               for a benign host.  The real server trims the old bytes away,
               while a DPI that rewrites its reassembly buffer with the newest
               segment sees the benign SNI instead of the blocked one.

``fake``       emit a decoy ClientHello with a low TTL (and a broken checksum by
               default) before the real data, so only the on-path DPI sees it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace

from .packet import (
    TCP_ACK,
    TCP_PSH,
    ClientHello,
    Packet,
    UDPPacket,
    build_fragments,
    build_segment,
    build_udp_datagram,
    build_udp_fragments,
    is_quic_initial,
    split_payload,
)
from .payloads import get as get_payload


@dataclass(slots=True)
class Step:
    delay_ms: float
    packets: list[bytes] = field(default_factory=list)


@dataclass(slots=True)
class Strategy:
    name: str = "seqovl"
    positions: str = "1"          # "1", "sni", "sni_mid", "half", "1,100", "none"
    seqovl: int = 0               # sequence overlap in bytes, 0 = disabled
    fake: bool = False            # send a decoy ClientHello first
    fake_ttl: int = 3
    fake_badsum: bool = True
    frag: bool = False            # split the first segment into IP fragments
    disorder: bool = False        # send segments out of order
    repeat: int = 1               # how many times to repeat the fake packet
    gap_ms: float = 0.0
    # A decoy SNI must be a host that the provider does not throttle.  A Google
    # name is a bad choice in regions where Google/YouTube are throttled too.
    fake_sni: str = "ya.ru"
    max_segment: int = 1400
    # Zapret-compatible knobs.  ``seqovl_pattern`` names a blob from
    # nadejda.payloads used to fill the overlapping part of the stream
    # ("decoy" keeps the generated ClientHello).  ``fake_payload`` names the
    # blob sent as the decoy; empty means the generated fake ClientHello.
    seqovl_pattern: str = "decoy"
    fake_payload: str = ""
    ip_id_zero: bool = False
    # How many data packets of a flow to desynchronise (SYN is not counted).
    # Zapret uses --dpi-desync-cutoff=n3/n4 for the same purpose.
    cutoff: int = 4

    def clone(self, **kwargs) -> "Strategy":
        return replace(self, **kwargs)


# Some providers do not merely inspect QUIC: they drop it per destination or
# reassemble IP fragments and block the ClientHello.  Fragmentation cannot fix
# that.  For those hosts QUIC is rejected, so the browser immediately falls
# back to TCP, where the normal desync strategy already works.
DEFAULT_FORCE_TCP = [
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "googlevideo.com",
    "ytimg.com",
    "gvt1.com",
    "gvt2.com",
    "googlesyndication.com",
    "doubleclick.net",
]


@dataclass(slots=True)
class UDPStrategy:
    """How to desynchronise QUIC (UDP/443) Initial packets.

    QUIC datagrams cannot be split like a TCP byte stream: every datagram is
    independent.  The reliable trick is IP fragmentation — the endpoint
    reassembles the datagram, while an on-path DPI that does not reassemble
    only ever sees the first (truncated) fragment.
    """

    name: str = "quic_frag"
    mode: str = "frag"          # "frag" | "fake" | "off"
    split: int = 64             # bytes of QUIC payload in the first fragment
    disorder: bool = True       # send the trailing fragment(s) first
    max_fragment: int = 1400    # IPv4/IPv6 fragment payload limit
    # "fake" mode (zapret-style): send a decoy datagram before the real one.
    # Zapret's general.bat does not use badsum or a low TTL for UDP: a home
    # NAT that drops INVALID packets would swallow a badsum fake before it
    # reaches the DPI, and TTL 3 may die before an ISP-level DPI.  A zero TTL
    # means "keep the original TTL"; the decoy is protocol-correct, so it is
    # harmless even when it reaches the server.
    fake_payload: str = "quic_google"
    fake_ttl: int = 0
    fake_badsum: bool = False
    repeat: int = 6
    fake_gap_ms: float = 0.0
    # Discord voice/screen-share (and game) UDP uses these ports.  A fake
    # datagram is sent for every new flow in this range; TURN/STUN on UDP/443
    # is never touched by the QUIC strategy.
    voice_payload: str = "discord_udp"
    voice_ttl: int = 0
    voice_badsum: bool = False
    voice_repeat: int = 3
    voice_gap_ms: float = 0.0
    # Domains for which QUIC is rejected even in "desync" mode.  Their TCP
    # traffic is still handled by the regular strategy.
    force_tcp_domains: list[str] = field(
        default_factory=lambda: list(DEFAULT_FORCE_TCP)
    )

    def clone(self, **kwargs) -> "UDPStrategy":
        return replace(self, **kwargs)


UDP_PRESETS: dict[str, UDPStrategy] = {
    # All variants keep the real datagram intact for the endpoint; only the
    # fragment layout seen by a DPI changes.
    "quic_frag": UDPStrategy(name="quic_frag", split=64, disorder=True),
    "quic_frag_early": UDPStrategy(name="quic_frag_early", split=32, disorder=True),
    "quic_frag_mid": UDPStrategy(name="quic_frag_mid", split=128, disorder=True),
    "quic_frag_inorder": UDPStrategy(name="quic_frag_inorder", split=64, disorder=False),
    "quic_off": UDPStrategy(name="quic_off", mode="off"),
    # Zapret's approach: inject a captured Google QUIC Initial before the real
    # one.  The decoy carries a benign SNI, so the DPI's per-flow verdict is
    # already made when the real Initial arrives.
    "zapret_quic": UDPStrategy(
        name="zapret_quic",
        mode="fake",
        fake_payload="quic_google",
        fake_ttl=0,
        fake_badsum=False,
        repeat=6,
    ),
    "zapret_game": UDPStrategy(
        name="zapret_game",
        mode="fake",
        # UDP/443 is still QUIC, so it needs a QUIC Initial as the decoy;
        # a game blob would be classified as a non-QUIC flow and dropped.
        fake_payload="quic_google",
        repeat=12,
        # The 19294-19344 / 50000-50100 ranges belong to Discord voice and
        # screen sharing even when the game filter is on, so they must use
        # zapret's ACTIVE_DISCORD_UDP blob, not the game one.
        voice_payload="discord_udp",
        voice_repeat=3,
    ),
}


def port_in_ranges(port: int, ranges) -> bool:
    """True when ``port`` is inside one of "443" / "1000-2000" entries."""
    for item in ranges or ():
        text = str(item).strip()
        if not text:
            continue
        try:
            if "-" in text:
                low, high = text.split("-", 1)
                if int(low) <= port <= int(high):
                    return True
            elif int(text) == port:
                return True
        except ValueError:
            continue
    return False


def _fake_udp_steps(
    pkt: UDPPacket,
    payload_name: str,
    repeat: int,
    ttl: int,
    badsum: bool,
    gap_ms: float,
    include_real: bool = True,
) -> list[Step] | None:
    decoy = get_payload(payload_name)
    if not decoy:
        return None
    packet = build_udp_datagram(pkt, decoy, ttl=ttl or None, badsum=badsum)
    steps = [Step(0.0, [packet] * max(1, int(repeat)))]
    if include_real:
        real = build_udp_datagram(pkt, pkt.payload)
        steps.append(Step(gap_ms, [real]))
    return steps


def build_udp_plan(
    pkt: UDPPacket,
    strategy: UDPStrategy,
    voice_ports=(),
    *,
    fakes_only: bool = False,
) -> list[Step] | None:
    """Return the packets to emit for one UDP datagram.

    UDP/443 is treated as QUIC (fragmented or preceded by a fake Initial).
    The Discord voice/screen-share ranges get a fake datagram before every
    real one.  TURN/STUN on 443 is deliberately left alone: it is not QUIC and
    fragmenting it breaks screen sharing.

    ``fakes_only`` omits the real datagram, for callers that will let the
    kernel deliver the original packet themselves (voice fast path).
    """
    voice = bool(voice_ports) and port_in_ranges(pkt.dport, voice_ports)
    if strategy.mode == "off" and not voice:
        # QUIC is disabled, but Discord voice / screen share must still be
        # protected: their fakes are independent of the QUIC strategy.
        return None
    if pkt.dport == 443:
        if not is_quic_initial(pkt.payload):
            return None
        if strategy.mode == "fake":
            return _fake_udp_steps(
                pkt,
                strategy.fake_payload,
                strategy.repeat,
                strategy.fake_ttl,
                strategy.fake_badsum,
                strategy.fake_gap_ms,
                include_real=not fakes_only,
            )
        packets = build_udp_fragments(
            pkt,
            strategy.split,
            disorder=strategy.disorder,
            max_fragment=strategy.max_fragment,
        )
        return [Step(0.0, packets)] if packets else None

    if voice_ports and port_in_ranges(pkt.dport, voice_ports):
        # Voice/video/STUN: zapret always precedes these datagrams with a fake
        # one, regardless of how QUIC is handled.
        return _fake_udp_steps(
            pkt,
            strategy.voice_payload,
            strategy.voice_repeat,
            strategy.voice_ttl,
            strategy.voice_badsum,
            strategy.voice_gap_ms,
            include_real=not fakes_only,
        )
    return None


def describe_udp(strategy: UDPStrategy) -> str:
    if strategy.mode == "off":
        return "QUIC выключен, голос Discord обрабатывается"
    if strategy.mode == "fake":
        return (
            f"fake({strategy.fake_payload} x{strategy.repeat}, "
            f"ttl={strategy.fake_ttl}, voice={strategy.voice_payload} "
            f"x{strategy.voice_repeat})"
        )
    order = "disorder" if strategy.disorder else "in-order"
    return f"ip-frag(split={strategy.split}, {order})"


# Presets are ordered roughly from "least invasive" to "most aggressive".
PRESETS: dict[str, Strategy] = {
    "seqovl568": Strategy(name="seqovl568", positions="1", seqovl=568, gap_ms=0),
    "seqovl_sni": Strategy(name="seqovl_sni", positions="sni_mid", seqovl=568, gap_ms=0),
    "seqovl300": Strategy(name="seqovl300", positions="1", seqovl=300, gap_ms=0),
    "multisplit": Strategy(name="multisplit", positions="1,sni_mid", gap_ms=10),
    "split1": Strategy(name="split1", positions="1", gap_ms=10),
    "split_sni": Strategy(name="split_sni", positions="sni_mid", gap_ms=10),
    "disorder": Strategy(name="disorder", positions="sni_mid", disorder=True, gap_ms=10),
    "fake_split": Strategy(name="fake_split", fake=True, fake_ttl=3, positions="sni_mid", gap_ms=10),
    "fake_split6": Strategy(
        name="fake_split6", fake=True, fake_ttl=6, positions="sni_mid", gap_ms=10, repeat=3
    ),
    "fake_seqovl": Strategy(
        name="fake_seqovl", fake=True, fake_ttl=3, positions="1", seqovl=568, gap_ms=0, repeat=2
    ),
    # The decoy must survive enough hops to reach the provider's DPI.  TTL 3 is
    # sometimes too small, so these presets let autotune probe deeper values.
    "fake_split_ttl6": Strategy(
        name="fake_split_ttl6", fake=True, fake_ttl=6, positions="sni_mid", gap_ms=10
    ),
    "fake_split_ttl9": Strategy(
        name="fake_split_ttl9", fake=True, fake_ttl=9, positions="sni_mid", gap_ms=10
    ),
    "fake_split_ttl12": Strategy(
        name="fake_split_ttl12", fake=True, fake_ttl=12, positions="sni_mid", gap_ms=10
    ),
    "fake_split_goodsum": Strategy(
        name="fake_split_goodsum",
        fake=True,
        fake_ttl=6,
        fake_badsum=False,
        positions="sni_mid",
        gap_ms=10,
    ),
    "fake_split_goodsum_ttl3": Strategy(
        name="fake_split_goodsum_ttl3",
        fake=True,
        fake_ttl=3,
        fake_badsum=False,
        positions="sni_mid",
        gap_ms=10,
    ),
    # Out-of-order delivery makes the provider's DPI keep the decoy SNI in its
    # reassembly buffer much more reliably than a plain split.
    "fake_split_goodsum_ttl3_disorder": Strategy(
        name="fake_split_goodsum_ttl3_disorder",
        fake=True,
        fake_ttl=3,
        fake_badsum=False,
        positions="sni_mid",
        gap_ms=10,
        disorder=True,
    ),
    "fake_seqovl_ttl6": Strategy(
        name="fake_seqovl_ttl6",
        fake=True,
        fake_ttl=6,
        fake_badsum=False,
        positions="1",
        seqovl=568,
        gap_ms=0,
        repeat=2,
    ),
    # ---- Zapret-compatible profiles -------------------------------------
    # Mirrors the command lines from Flowseal/zapret-discord-youtube
    # general.bat: multisplit at position 1 with a 568-byte sequence overlap
    # filled by a real 4PDA ClientHello, or 681 bytes of a Google ClientHello
    # for Google/Discord-media destinations (plus ip-id=zero).
    "zapret_general": Strategy(
        name="zapret_general",
        positions="1",
        seqovl=568,
        seqovl_pattern="tls_4pda",
        gap_ms=0,
    ),
    "zapret_google": Strategy(
        name="zapret_google",
        positions="1",
        seqovl=681,
        seqovl_pattern="tls_google",
        ip_id_zero=True,
        gap_ms=0,
    ),
    "zapret_discord": Strategy(
        name="zapret_discord",
        positions="1",
        seqovl=681,
        seqovl_pattern="tls_google",
        gap_ms=0,
    ),
    # ALT variant: fake decoy plus a sequence-overlap split.  Zapret uses
    # --dpi-desync=fake,fakedsplit with --dpi-desync-repeats=6 and the
    # "ts"/checksum fooling; here the decoy carries a broken checksum and a
    # low TTL, which has the same effect (DPI sees it, the server drops it).
    "zapret_fake": Strategy(
        name="zapret_fake",
        fake=True,
        fake_ttl=3,
        fake_badsum=True,
        fake_payload="tls_google",
        positions="1",
        seqovl=568,
        seqovl_pattern="tls_4pda",
        gap_ms=0,
        repeat=6,
    ),
    # The first try of a flow is a fake ClientHello; the following data
    # packets are split with the STUN decoy as well (fakedsplit-style).
    "zapret_fake_fakedsplit": Strategy(
        name="zapret_fake_fakedsplit",
        fake=True,
        fake_ttl=3,
        fake_badsum=True,
        fake_payload="stun",
        positions="1",
        seqovl=568,
        seqovl_pattern="tls_4pda",
        gap_ms=0,
        repeat=6,
    ),
    "frag": Strategy(name="frag", positions="none", frag=True),
    "frag_split": Strategy(name="frag_split", positions="sni_mid", frag=True, gap_ms=10),
    "split1_disorder": Strategy(
        name="split1_disorder", positions="1,sni_mid", disorder=True, gap_ms=10
    ),
}


def apply_config(strategy: Strategy, cfg) -> Strategy:
    """Overlay user configuration on top of a preset."""
    return strategy.clone(
        fake_ttl=getattr(cfg, "fake_ttl", strategy.fake_ttl),
        fake_badsum=getattr(cfg, "fake_badsum", strategy.fake_badsum),
        gap_ms=getattr(cfg, "gap_ms", strategy.gap_ms),
        repeat=getattr(cfg, "repeat", strategy.repeat),
        fake_sni=getattr(cfg, "fake_sni", strategy.fake_sni),
        max_segment=getattr(cfg, "max_segment", strategy.max_segment),
    )


def _resolve_positions(hello: ClientHello | None, payload_len: int, spec: str) -> list[int]:
    spec = (spec or "").strip().lower()
    if not spec or spec == "none":
        return []
    result: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        try:
            if part == "1":
                result.append(1)
            elif part in ("sni", "sni_start"):
                if hello and hello.sni_offset:
                    result.append(hello.sni_offset + 1)
            elif part == "sni_mid":
                if hello and hello.sni_offset:
                    result.append(hello.sni_offset + max(1, hello.sni_len // 2))
            elif part == "sni_end":
                if hello and hello.sni_offset:
                    result.append(hello.sni_offset + hello.sni_len - 1)
            elif part == "half":
                result.append(payload_len // 2)
            elif part.isdigit():
                result.append(int(part))
        except ValueError:
            continue
    return sorted({p for p in result if 0 < p < payload_len})


def _overlap_pattern(strategy: Strategy, decoy: bytes) -> bytes:
    """Bytes that fill the sequence overlap.

    Zapret's ``--dpi-desync-split-seqovl-pattern`` files are shorter than the
    overlap for some profiles (284 bytes vs 568), so repeat them cyclically.
    """
    name = (strategy.seqovl_pattern or "").strip()
    if name and name != "decoy":
        raw = get_payload(name)
        if raw:
            need = max(1, int(strategy.seqovl))
            return (raw * (need // len(raw) + 1))[:need]
    return decoy


def build_plan(
    pkt: Packet,
    hello: ClientHello | None,
    strategy: Strategy,
    decoy: bytes,
    fake_decoy: bytes | None = None,
) -> list[Step] | None:
    payload = pkt.payload
    if len(payload) < 12:
        return None

    seq = pkt.seq
    positions = _resolve_positions(hello, len(payload), strategy.positions)
    pieces: list[tuple[int, bytes]] = []

    if strategy.seqovl and positions:
        split_at = positions[0]
        pattern = _overlap_pattern(strategy, decoy)
        overlap = min(int(strategy.seqovl), len(pattern))
        if overlap >= split_at:
            # Match zapret's multisplit exactly: the *first* segment sent is
            # the sequence-overlap segment.  It starts ``overlap`` bytes before
            # the real payload, is filled with the decoy blob, and ends with
            # the first ``split_at`` real bytes.  The rest of the payload is
            # sent afterwards starting at ``seq + split_at``.
            #
            # Sending the 1-byte head first (as this code used to do) let the
            # DPI anchor its reassembly at ``seq`` and parse the real SNI in
            # the following segment; the flow was then throttled after the
            # initial TCP window.  zapret sends the decoy segment first, so
            # the DPI sees the decoy ClientHello and classifies the flow by it.
            head_seq = (seq - overlap) & 0xFFFFFFFF
            head = pattern[:overlap] + payload[:split_at]
            pieces.append((head_seq, head))
            pieces.extend(
                split_payload(
                    pkt,
                    payload[split_at:],
                    [],
                    strategy.max_segment,
                    start_seq=(seq + split_at) & 0xFFFFFFFF,
                )
            )
        else:
            pieces = split_payload(pkt, payload, positions, strategy.max_segment)
    elif strategy.frag and not positions:
        pieces = [(seq, payload)]
    else:
        pieces = split_payload(pkt, payload, positions, strategy.max_segment)

    if not pieces:
        return None

    steps: list[Step] = []
    flags = (pkt.flags | TCP_PSH | TCP_ACK) & 0xFF
    ip_id = 0 if strategy.ip_id_zero else None

    fake_data = get_payload(strategy.fake_payload) if strategy.fake_payload else b""
    if not fake_data:
        fake_data = fake_decoy or decoy
    if strategy.fake and fake_data:
        fake = build_segment(
            pkt,
            seq,
            fake_data,
            flags=flags,
            ttl=strategy.fake_ttl,
            ip_id=ip_id,
            badsum=strategy.fake_badsum,
        )
        for _ in range(max(1, strategy.repeat)):
            steps.append(Step(0.0, [fake]))

    if strategy.frag:
        first_seq, first_data = pieces[0]
        first_packets = build_fragments(pkt, first_seq, first_data, flags=flags)
        steps.append(Step(0.0, first_packets))
        pieces = pieces[1:]

    order = list(pieces)
    if strategy.disorder and len(order) > 1:
        order.reverse()

    for index, (piece_seq, data) in enumerate(order):
        # After a fake decoy, pause briefly before the real ClientHello so the
        # DPI definitely processes the decoy first.  Without this the two can
        # race and the provider sees the real SNI, which triggers throttling.
        delay = 0.0 if index == 0 else strategy.gap_ms
        if index == 0 and strategy.fake and steps and strategy.gap_ms:
            delay = strategy.gap_ms
        steps.append(
            Step(
                delay,
                [
                    build_segment(
                        pkt,
                        piece_seq,
                        data,
                        flags=flags,
                        ttl=pkt.ttl,
                        ip_id=ip_id,
                    )
                ],
            )
        )

    return steps or None


def describe(strategy: Strategy) -> str:
    bits = []
    if strategy.fake:
        bits.append(
            f"fake(ttl={strategy.fake_ttl},repeat={strategy.repeat}"
            + (f",{strategy.fake_payload}" if strategy.fake_payload else "")
            + ")"
        )
    if strategy.seqovl:
        suffix = ""
        if strategy.seqovl_pattern and strategy.seqovl_pattern != "decoy":
            suffix = f",{strategy.seqovl_pattern}"
        bits.append(f"seqovl({strategy.seqovl}{suffix})")
    if strategy.ip_id_zero:
        bits.append("ip-id=0")
    if strategy.frag:
        bits.append("frag")
    if strategy.disorder:
        bits.append("disorder")
    if strategy.positions != "none" or not bits:
        bits.append(f"split({strategy.positions})")
    return "+".join(bits)
