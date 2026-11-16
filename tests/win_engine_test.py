#!/usr/bin/env python3
"""Windows engine tests.

These run on Linux as an ordinary user: the strategy layer is portable and the
WinDivert handle is replaced with a fake object.  No root, no pydivert and no
real network traffic are needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nadejda import config as configmod  # noqa: E402
from nadejda.hostlist import HostList  # noqa: E402
from nadejda.packet import is_quic_initial, make_client_hello  # noqa: E402
from nadejda.payloads import get as get_payload  # noqa: E402
from nadejda.win.cli import _hello_covered, tcp_packet, udp_packet  # noqa: E402
from nadejda.win.divert import CapturedPacket  # noqa: E402
from nadejda.win.engine import WinEngine, build_filter  # noqa: E402

FAILED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"ok   {name}")
    else:
        FAILED += 1
        print(f"FAIL {name}" + (f" — {detail}" if detail else ""))


def fresh_config() -> configmod.Config:
    return configmod.load(ROOT / "config" / "config.toml")


def pick_plain_domain(cfg: configmod.Config) -> str:
    """A listed domain that is not covered by an [overrides] entry."""
    overridden = HostList(list(cfg.overrides))
    for domain in cfg.domains:
        if not overridden.matches(domain):
            return domain
    raise AssertionError("every listed domain has an override")


class FakeHandle:
    """Minimal stand-in for WinDivertHandle."""

    is_open = True

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.checksums: list[tuple[bool, bool, bool] | None] = []

    def send(self, raw: bytes, interface=None, checksums=None) -> None:
        self.sent.append(raw)
        self.checksums.append(checksums)

    def close(self) -> None:
        pass


def test_filter(cfg: configmod.Config) -> None:
    win_filter = build_filter(cfg)
    check("filter is outbound-only", win_filter.startswith("outbound and not loopback"))
    check("filter skips loopback traffic", "not loopback" in win_filter)
    check("filter requires a TCP payload", "tcp.PayloadLength > 0" in win_filter)
    check("filter covers QUIC", "udp.DstPort == 443" in win_filter)
    check("filter parentheses are balanced", win_filter.count("(") == win_filter.count(")"))
    check(
        "filter contains every TCP port",
        all(f"tcp.DstPort == {port}" in win_filter for port in cfg.general.tcp_ports),
    )
    check(
        "filter contains voice ranges",
        "udp.DstPort >= 19294" in win_filter and "udp.DstPort <= 50100" in win_filter,
    )

    off = fresh_config()
    off.general.quic = "off"
    check("quic=off removes UDP/443 from the filter", "udp.DstPort == 443" not in build_filter(off))


def test_tcp(cfg: configmod.Config) -> None:
    engine = WinEngine(cfg)
    domain = pick_plain_domain(cfg)
    hello = make_client_hello(domain)

    decision = engine.process(tcp_packet(hello, 443, 1000, sport=50000))
    check("listed ClientHello is dropped", decision.drop)
    check("listed ClientHello produces packets", len(decision.packets) > 0)
    check(
        "every ClientHello byte is preserved",
        _hello_covered(decision.packets, hello, 1000),
    )
    check("desync counter incremented", engine.stats_snapshot()["stats"]["desynced"] == 1)

    unlisted = make_client_hello("example.org")
    decision = engine.process(tcp_packet(unlisted, 443, 2000, sport=50001))
    check("unlisted ClientHello is passed through", not decision.drop and not decision.packets)

    excluded_domain = cfg.exclude[0]
    excluded = make_client_hello(f"www.{excluded_domain}")
    decision = engine.process(tcp_packet(excluded, 443, 3000, sport=50002))
    check(
        f"excluded domain ({excluded_domain}) is passed through",
        not decision.drop and not decision.packets,
    )

    # The first data packet of a desynchronised flow is rewritten once, the
    # second one is left alone (cutoff).
    data_seq = 1000 + len(hello)
    decision = engine.process(tcp_packet(b"GET / HTTP/1.1\r\n", 443, data_seq, sport=50000))
    check("first data packet is desynchronised", decision.drop and bool(decision.packets))
    decision = engine.process(
        tcp_packet(b"Host: example\r\n", 443, data_seq + 16, sport=50000)
    )
    check("second data packet is passed through", not decision.drop)


def test_partial(cfg: configmod.Config) -> None:
    engine = WinEngine(cfg)
    domain = pick_plain_domain(cfg)
    hello = make_client_hello(domain)
    split = 300

    first = tcp_packet(hello[:split], 443, 7000, sport=50003)
    decision = engine.process(first)
    check("first ClientHello segment is buffered", decision.drop and not decision.packets)

    second = tcp_packet(hello[split:], 443, 7000 + split, sport=50003)
    decision = engine.process(second)
    check("second segment completes the record", decision.drop and bool(decision.packets))
    check(
        "reassembled ClientHello keeps every byte",
        _hello_covered(decision.packets, hello, 7000),
    )
    check(
        "reassembly counter incremented",
        engine.stats_snapshot()["stats"]["reassembled"] == 0,
        "a desynchronised record must not count as a plain re-injection",
    )

    # A retransmission of the first segment must not corrupt the buffer.
    engine2 = WinEngine(cfg)
    engine2.process(tcp_packet(hello[:split], 443, 8000, sport=50004))
    engine2.process(tcp_packet(hello[:split], 443, 8000, sport=50004))
    decision = engine2.process(tcp_packet(hello[split:], 443, 8000 + split, sport=50004))
    check(
        "retransmitted first segment is tolerated",
        decision.drop and _hello_covered(decision.packets, hello, 8000),
    )


def test_udp(cfg: configmod.Config) -> None:
    engine = WinEngine(cfg)
    blob = get_payload("quic_google")
    check("QUIC test payload exists", bool(blob) and is_quic_initial(blob))

    decision = engine.process(udp_packet(blob, 443, sport=50010))
    check("QUIC Initial is fragmented", decision.drop and len(decision.packets) >= 2)
    check(
        "QUIC fragments are IPv4 packets",
        all(raw[0] >> 4 == 4 for raw in decision.packets),
    )

    decision = engine.process(udp_packet(b"\x00" * 40, 443, sport=50011))
    check("non-QUIC UDP/443 is passed through", not decision.drop)

    voice = get_payload("discord_udp")
    check("Discord voice payload exists", bool(voice))
    decision = engine.process(udp_packet(voice, 50000, sport=50012))
    check("Discord voice gets a fake datagram", decision.drop and len(decision.packets) >= 2)
    check(
        "voice counter incremented",
        engine.stats_snapshot()["stats"]["voice_desynced"] == 1,
    )

    blocked_cfg = fresh_config()
    blocked_cfg.general.quic = "block"
    blocked = WinEngine(blocked_cfg)
    decision = blocked.process(udp_packet(blob, 443, sport=50013))
    check("quic=block drops the Initial without a replacement", decision.drop and not decision.packets)


def test_overrides(cfg: configmod.Config) -> None:
    engine = WinEngine(cfg)
    check(
        "googlevideo.com override is present",
        cfg.overrides.get("googlevideo.com") == "split_sni",
        repr(cfg.overrides.get("googlevideo.com")),
    )
    strategy, _, _ = engine._select_strategy("rr1---sn-abc.googlevideo.com")
    check("override is selected by suffix", strategy.name == "split_sni")
    strategy, _, _ = engine._select_strategy("www.youtube.com")
    check(
        "youtube.com override is selected",
        strategy.name == cfg.overrides["youtube.com"],
    )
    strategy, _, _ = engine._select_strategy("example.org")
    check("unknown host falls back to the global strategy", strategy.name == cfg.strategy.name)


def test_handle_plumbing(cfg: configmod.Config) -> None:
    fake = FakeHandle()
    engine = WinEngine(cfg, handle=fake)
    domain = pick_plain_domain(cfg)
    hello = make_client_hello(domain)
    raw = tcp_packet(hello, 443, 9000, sport=50020)

    engine.handle_captured(CapturedPacket(raw=raw, interface=(1, 0)))
    check("original desynchronised packet is not injected", raw not in fake.sent)
    check("plan packets are injected", len(fake.sent) > 0)
    check("injected counter incremented", engine.stats_snapshot()["stats"]["injected"] > 0)
    check(
        "engine-built packets keep final checksums",
        all(flags is None for flags in fake.checksums),
        repr(fake.checksums),
    )

    fake.sent.clear()
    fake.checksums.clear()
    unlisted = tcp_packet(make_client_hello("example.org"), 443, 9100, sport=50021)
    engine.handle_captured(
        CapturedPacket(
            raw=unlisted,
            interface=(1, 0),
            ip_checksum=True,
            tcp_checksum=True,
        )
    )
    check("accepted packet is re-injected unchanged", fake.sent == [unlisted])
    check(
        "captured checksum flags are preserved on pass-through",
        fake.checksums == [(True, True, False)],
        repr(fake.checksums),
    )
    check("passed counter incremented", engine.stats_snapshot()["stats"]["passed"] == 1)


def main() -> int:
    cfg = fresh_config()
    test_filter(cfg)
    test_tcp(cfg)
    test_partial(cfg)
    test_udp(cfg)
    test_overrides(cfg)
    test_handle_plumbing(cfg)
    if FAILED:
        print(f"\n{FAILED} check(s) failed")
        return 1
    print("\nall Windows engine checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
