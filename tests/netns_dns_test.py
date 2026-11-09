#!/usr/bin/env python3
"""End-to-end test of the transparent DNS proxy inside a network namespace.

Checks that the nftables *nat* chain really redirects outgoing port-53 traffic
to the local proxy, that UDP and TCP queries are answered, that the cache
works, and that fwmark-protected packets are not redirected (otherwise the
proxy would forward its own queries into itself).

Run:  unshare -Urn python3 tests/netns_dns_test.py
"""

from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nadejda.dnsserver import DNSServer  # noqa: E402
from nadejda.firewall import Firewall, FirewallConfig  # noqa: E402
from nadejda.resolver import build_query, parse_answers, parse_question  # noqa: E402

PORT = 5353
MARK = 0x4E414445
FAKE_IP = "1.2.3.4"


def sh(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True).stdout


class FakeResolver:
    """Answers every A query with FAKE_IP, counting upstream calls."""

    def __init__(self) -> None:
        self.calls = 0

    def query_raw(self, packet: bytes) -> bytes:
        self.calls += 1
        question = parse_question(packet)
        assert question is not None
        _name, _qtype, _qclass, end = question
        qid = struct.unpack("!H", packet[:2])[0]
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(FAKE_IP)
        return header + packet[12:end] + answer


def parse_a(response: bytes) -> str | None:
    _rcode, answers = parse_answers(response)
    for _name, rtype, _ttl, rdata in answers:
        if rtype == 1 and len(rdata) == 4:
            return socket.inet_ntoa(rdata)
    return None


def udp_query(query: bytes, timeout: float = 2.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(timeout)
        sock.sendto(query, ("8.8.8.8", 53))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def tcp_query(query: bytes, timeout: float = 3.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(timeout)
        sock.connect(("8.8.8.8", 53))
        sock.sendall(struct.pack("!H", len(query)) + query)
        header = sock.recv(2)
        assert len(header) == 2
        length = struct.unpack("!H", header)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


def main() -> int:
    failures = 0

    def check(ok: bool, text: str) -> None:
        nonlocal failures
        print(f"  {'[ok]  ' if ok else '[FAIL]'} {text}")
        if not ok:
            failures += 1

    sh("ip link set lo up")
    # Locally generated packets need a route before they reach the output hook.
    sh("ip route add default dev lo")

    resolver = FakeResolver()
    dns = DNSServer(resolver, port=PORT, cache_ttl=3600)
    firewall = Firewall(
        FirewallConfig(
            queue_num=42,
            mark=MARK,
            scope="all",
            block_quic="off",
            dns=True,
            dns_port=PORT,
        )
    )
    try:
        dns.start()
        firewall.apply()
        check(firewall.exists(), "nftables table with nat DNS redirect installed")

        query = build_query("example.com", 1, 0x1234)
        response = udp_query(query)
        check(response[:2] == query[:2], "UDP: response id matches the query")
        check(parse_a(response) == FAKE_IP, f"UDP: redirected and answered ({parse_a(response)})")

        calls_before = resolver.calls
        response = udp_query(query)
        check(parse_a(response) == FAKE_IP and resolver.calls == calls_before,
              "UDP: second query served from cache")

        response = tcp_query(build_query("example.org", 1, 0x4321))
        check(parse_a(response) == FAKE_IP, "TCP: redirected and answered")

        # A marked socket must bypass the redirect, otherwise the resolver's own
        # upstream queries would loop back into the proxy forever.
        calls_before = resolver.calls
        marked = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            marked.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARK)
            marked.settimeout(0.6)
            marked.sendto(build_query("marked.example", 1), ("8.8.8.8", 53))
            try:
                marked.recvfrom(4096)
                timed_out = False
            except socket.timeout:
                timed_out = True
        finally:
            marked.close()
        check(timed_out and resolver.calls == calls_before, "fwmark bypasses the DNS redirect")
    finally:
        firewall.remove(quiet=True)
        dns.stop()

    print("FAILURES:", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
