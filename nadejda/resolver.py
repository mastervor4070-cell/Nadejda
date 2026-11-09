"""DNS over TLS / DNS over UDP resolver used for hostlist and as a local proxy.

The ISP resolver cannot be trusted on a censored network (it returns sinkhole
addresses for blocked domains), so Nadejda talks to public resolvers over TLS
and only falls back to plain UDP when there is no other option.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import ssl
import struct
import threading
import time

log = logging.getLogger(__name__)

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_AAAA = 28
QTYPE_TXT = 16

TYPE_BY_NAME = {"A": QTYPE_A, "AAAA": QTYPE_AAAA, "CNAME": QTYPE_CNAME, "TXT": QTYPE_TXT}

SO_MARK = getattr(socket, "SO_MARK", 25)

DOT_NAMES = {
    "1.1.1.1": "cloudflare-dns.com",
    "1.0.0.1": "cloudflare-dns.com",
    "8.8.8.8": "dns.google",
    "8.8.4.4": "dns.google",
    "9.9.9.9": "dns.quad9.net",
    "149.112.112.112": "dns.quad9.net",
}


class DNSError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# wire format
# --------------------------------------------------------------------------


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii", "replace")
        if not raw or len(raw) > 63:
            raise DNSError(f"bad label in {name!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end = offset
    jumped = False
    seen = 0
    while True:
        if offset >= len(data):
            raise DNSError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            seen += 1
            if seen > 20:
                raise DNSError("compression loop")
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), end


def build_query(name: str, qtype: int, qid: int | None = None) -> bytes:
    qid = random.getrandbits(16) if qid is None else qid
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def parse_question(data: bytes) -> tuple[str, int, int, int] | None:
    if len(data) < 12:
        return None
    _qid, _flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if qd < 1:
        return None
    try:
        name, offset = decode_name(data, 12)
    except DNSError:
        return None
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return name.lower(), qtype, qclass, offset + 4


def parse_answers(data: bytes) -> tuple[int, list[tuple[str, int, int, bytes]]]:
    if len(data) < 12:
        raise DNSError("short response")
    _qid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x0F
    offset = 12
    for _ in range(qd):
        _name, offset = decode_name(data, offset)
        offset += 4
    answers: list[tuple[str, int, int, bytes]] = []
    for _ in range(an):
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise DNSError("truncated answer")
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        answers.append((name.lower(), rtype, ttl, rdata))
    return rcode, answers


def min_ttl(data: bytes, default: int = 60) -> int:
    try:
        _rcode, answers = parse_answers(data)
    except DNSError:
        return default
    ttls = [ttl for _n, _t, ttl, *_ in answers if ttl > 0]
    return min(ttls) if ttls else default


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------


class Resolver:
    def __init__(
        self,
        servers: list[str] | None = None,
        *,
        mark: int = 0,
        timeout: float = 5.0,
        fallback_udp: bool = True,
    ):
        self.servers = list(servers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        self.mark = mark
        self.timeout = timeout
        self.fallback_udp = fallback_udp and mark != 0
        self._index = 0
        self._sock: ssl.SSLSocket | None = None
        self._sock_server: str | None = None
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, int], tuple[float, list[str]]] = {}

    # -- sockets ------------------------------------------------------------

    def _new_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.mark:
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self.mark)
            except OSError as exc:
                log.debug("cannot set SO_MARK on resolver socket: %s", exc)
        return sock

    def _connect_dot(self, ip: str) -> ssl.SSLSocket:
        sock = self._new_socket()
        sock.settimeout(self.timeout)
        sock.connect((ip, 853))
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=DOT_NAMES.get(ip, ip))
        self._sock = tls
        self._sock_server = ip
        return tls

    def _close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._sock_server = None

    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = sock.recv(size - len(chunks))
            if not chunk:
                raise ConnectionError("resolver closed the connection")
            chunks.extend(chunk)
        return bytes(chunks)

    def _query_dot(self, packet: bytes) -> bytes:
        with self._lock:
            last_error: Exception | None = None
            for _ in range(len(self.servers)):
                ip = self.servers[self._index]
                try:
                    if self._sock is None or self._sock_server != ip:
                        self._close()
                        self._connect_dot(ip)
                    assert self._sock is not None
                    self._sock.sendall(struct.pack("!H", len(packet)) + packet)
                    length = struct.unpack("!H", self._recv_exact(self._sock, 2))[0]
                    response = self._recv_exact(self._sock, length)
                    if response[:2] != packet[:2]:
                        raise DNSError("resolver returned a mismatched id")
                    return response
                except Exception as exc:  # noqa: BLE001 - fail over to the next server
                    last_error = exc
                    log.warning("DoT %s failed: %s", ip, exc)
                    self._close()
                    self._index = (self._index + 1) % len(self.servers)
            if self.fallback_udp:
                return self._query_udp(packet)
            raise DNSError(f"all DNS-over-TLS servers failed: {last_error}")

    def _udp_servers(self) -> list[str]:
        result: list[str] = []
        try:
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        ip = parts[1]
                        if ip.startswith("127.") or ip in ("::1", "0.0.0.0"):
                            continue
                        result.append(ip)
        except OSError:
            pass
        return result or self.servers

    def _query_udp(self, packet: bytes) -> bytes:
        for ip in self._udp_servers():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                if self.mark:
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self.mark)
                sock.settimeout(self.timeout)
                sock.sendto(packet, (ip, 53))
                response, _ = sock.recvfrom(65535)
                return response
            except OSError as exc:
                log.warning("UDP DNS %s failed: %s", ip, exc)
            finally:
                sock.close()
        raise DNSError("no DNS upstream available")

    # -- public -------------------------------------------------------------

    def query_raw(self, packet: bytes) -> bytes:
        return self._query_dot(packet)

    def resolve(self, name: str, qtype: int = QTYPE_A, *, use_cache: bool = True) -> list[str]:
        key = (name.lower(), qtype)
        now = time.time()
        if use_cache:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                return hit[1]
        packet = build_query(name, qtype)
        response = self.query_raw(packet)
        rcode, answers = parse_answers(response)
        if rcode not in (0, 3):
            raise DNSError(f"DNS rcode {rcode} for {name}")
        values: list[str] = []
        cname: str | None = None
        for rname, rtype, _ttl, rdata in answers:
            if rtype == qtype:
                if rtype == QTYPE_A and len(rdata) == 4:
                    values.append(socket.inet_ntoa(rdata))
                elif rtype == QTYPE_AAAA and len(rdata) == 16:
                    values.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype == QTYPE_CNAME:
                try:
                    cname, _ = decode_name(rdata, 0)
                except DNSError:
                    pass
        if not values and cname and cname.lower() != name.lower():
            values = self.resolve(cname, qtype, use_cache=False)
        ttl = max(30, min(min_ttl(response, 60), 3600))
        self._cache[key] = (now + ttl, values)
        return values

    def resolve_many(self, names: list[str]) -> tuple[list[str], list[str]]:
        v4: set[str] = set()
        v6: set[str] = set()
        for name in names:
            try:
                v4.update(self.resolve(name, QTYPE_A))
            except Exception as exc:  # noqa: BLE001
                log.debug("A lookup failed for %s: %s", name, exc)
            try:
                v6.update(self.resolve(name, QTYPE_AAAA))
            except Exception as exc:  # noqa: BLE001
                log.debug("AAAA lookup failed for %s: %s", name, exc)
        return sorted(v4), sorted(v6)

    def close(self) -> None:
        with self._lock:
            self._close()
