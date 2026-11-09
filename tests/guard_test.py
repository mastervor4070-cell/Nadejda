#!/usr/bin/env python3
"""Tests for the stalled-flow reset (works as an unprivileged user)."""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nadejda import config as configmod  # noqa: E402
from nadejda.desync import PRESETS  # noqa: E402
from nadejda.engine import Engine  # noqa: E402
from nadejda.packet import (  # noqa: E402
    TCP_ACK,
    TCP_PSH,
    TCP_RST,
    checksum,
    make_client_hello,
    parse_client_hello,
    parse_packet,
)

FAILED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"ok   {name}")
    else:
        FAILED += 1
        print(f"FAIL {name}" + (f": {detail}" if detail else ""))


def client_packet(seq: int, ack: int, payload: bytes, sport: int = 40000):
    tcp = struct.pack(
        "!HHIIBBHHH", sport, 443, seq, ack, 5 << 4, TCP_PSH | TCP_ACK, 65535, 0, 0
    ) + payload
    pseudo = (
        socket.inet_aton("192.0.2.10")
        + socket.inet_aton("192.0.2.20")
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
        socket.inet_aton("192.0.2.10"),
        socket.inet_aton("192.0.2.20"),
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    pkt = parse_packet(ip + tcp)
    assert pkt is not None
    return pkt


def make_engine() -> Engine:
    cfg = configmod.Config(
        general=configmod.GeneralConfig(dns=False, quic="off", scope="all"),
        strategy=PRESETS["multisplit"].clone(),
        domains=["example.com"],
        path=Path("/nonexistent/config.toml"),
    )
    return Engine(cfg)


def main() -> int:
    payload = make_client_hello("example.com")
    hello = parse_client_hello(payload)
    check("guard: test hello has SNI", hello is not None and hello.sni == "example.com")
    engine = make_engine()
    sent: list = []
    engine.sender.submit = lambda plan: sent.append(plan) or True  # type: ignore[method-assign]

    check("guard: disabled when no ClientHello and flow unknown", not engine._check_stall(client_packet(100, 500, b"x" * 300), None))

    # A ClientHello that matches the host list starts tracking, but the first
    # two sightings must not reset anything yet.
    pkt1 = client_packet(100, 500, payload)
    check("guard: first hello accepted", not engine._check_stall(pkt1, hello))
    check("guard: second hello accepted", not engine._check_stall(pkt1, hello))
    check("guard: no reset yet", not sent)

    # After STALL_MIN_AGE the third identical sighting is a real stall.
    time.sleep(1.05)
    reset = engine._check_stall(pkt1, hello)
    check("guard: third hello after a second resets", reset)
    check("guard: one reset packet sent", len(sent) == 1 and len(sent[0]) == 1)
    check("guard: reset counted", engine.stats["stall_resets"] == 1)

    rst = parse_packet(sent[0][0].packets[0])
    check("reset: parses", rst is not None)
    if rst is not None:
        check("reset: comes from the server", rst.src == "192.0.2.20" and rst.sport == 443)
        check("reset: goes to the client", rst.dst == "192.0.2.10" and rst.dport == 40000)
        check("reset: flags RST|ACK", rst.flags == (TCP_RST | TCP_ACK))
        check("reset: seq is the client's rcv_nxt", rst.seq == 500)
        check("reset: ack covers the hello", rst.ack == 100 + len(payload))

        tcp = sent[0][0].packets[0][20:]
        pseudo = (
            socket.inet_aton("192.0.2.20")
            + socket.inet_aton("192.0.2.10")
            + struct.pack("!BBH", 0, 6, len(tcp))
        )
        check("reset: TCP checksum valid", checksum(pseudo + tcp) == 0)
        ip = sent[0][0].packets[0][:20]
        check("reset: IP checksum valid", checksum(ip) == 0)

    # A different payload on the same flow means the handshake progressed:
    # the retransmission counter must restart, not fire.
    engine2 = make_engine()
    sent2: list = []
    engine2.sender.submit = lambda plan: sent2.append(plan) or True  # type: ignore[method-assign]
    hello_pkt = client_packet(200, 600, payload, sport=40001)
    data_pkt = client_packet(200 + len(payload), 600, b"GET / HTTP/1.1\r\n" + b"x" * 300, sport=40001)
    check("guard2: hello tracked", not engine2._check_stall(hello_pkt, hello))
    check("guard2: data is different", not engine2._check_stall(data_pkt, None))
    check("guard2: data repeat 1", not engine2._check_stall(data_pkt, None))
    time.sleep(1.05)
    check("guard2: data repeat 2 resets", engine2._check_stall(data_pkt, None))

    # The feature can be switched off.
    engine3 = make_engine()
    engine3.general.stall_reset = False
    engine3.sender.submit = lambda plan: sent.append(plan) or True  # type: ignore[method-assign]
    for _ in range(4):
        engine3._check_stall(pkt1, hello)
    check("guard: stall_reset=false disables it", engine3.stats["stall_resets"] == 0)

    # Startup cleanup: only sockets that the peer never acknowledged and that
    # are already in retransmission backoff are considered dead.
    ss_sample = (
        "ESTAB      0      0      192.168.3.49:51968     172.64.41.4:443\n"
        "\t cubic rto:263 rtt:62.691/4.046 mss:1388 "
        "bytes_sent:3535 bytes_acked:1 retrans:0/6 backoff:6 lastrcv:27058\n"
        "ESTAB      0      0      192.168.3.49:54376   35.186.224.24:443\n"
        "\t cubic rto:264 rtt:63.984/8.759 mss:1388 "
        "bytes_sent:2883 bytes_acked:2884 retrans:0/0 backoff:0 lastrcv:12\n"
        "ESTAB      0      0      192.168.3.49:40000      1.1.1.1:853\n"
        "\t cubic rto:264 bytes_sent:100 bytes_acked:1 backoff:4 lastrcv:60000\n"
        "ESTAB      0      0      192.168.3.49:41000   93.184.216.34:443\n"
        "\t cubic rto:264 bytes_sent:100 bytes_acked:1 backoff:0 lastrcv:60000\n"
    )
    stuck = Engine._stuck_from_ss(ss_sample)
    check("cleanup: finds the black-holed socket", stuck == [("172.64.41.4", 51968, 443)], repr(stuck))
    check("cleanup: keeps healthy sockets", len(stuck) == 1)
    check("cleanup: empty output", Engine._stuck_from_ss("") == [])

    if FAILED:
        print(f"\n{FAILED} check(s) failed")
        return 1
    print("\nguard tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
