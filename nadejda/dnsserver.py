"""A small transparent DNS proxy.

Two jobs:

* answer local stub-resolver queries from a clean (DNS-over-TLS) cache, so the
  ISP cannot poison results for blocked domains;
* optionally strip AAAA records to keep traffic on the IPv4 path that the
  desync engine handles.

The nftables ruleset redirects every outgoing port-53 packet here, so no
changes to ``/etc/resolv.conf`` or NetworkManager are required.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import threading
import time

from .resolver import min_ttl, parse_question

log = logging.getLogger(__name__)


class DNSServer:
    def __init__(
        self,
        resolver,
        port: int = 5353,
        *,
        strip_aaaa: bool = False,
        cache_ttl: int = 3600,
    ):
        self.resolver = resolver
        self.port = port
        self.strip_aaaa = strip_aaaa
        self.cache_ttl = cache_ttl
        self._cache: dict[tuple[str, int, int], tuple[float, bytes]] = {}
        self._cache_lock = threading.Lock()
        self._sockets: list[socket.socket] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.queries = 0
        self.cache_hits = 0

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            try:
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((address, self.port))
                sock.setblocking(False)
                self._sockets.append(sock)
            except OSError as exc:
                log.warning("cannot bind DNS proxy on [%s]:%d: %s", address, self.port, exc)
        if not self._sockets:
            raise RuntimeError("DNS proxy could not bind any address")
        thread = threading.Thread(target=self._udp_loop, name="dns-udp", daemon=True)
        thread.start()
        self._threads.append(thread)
        for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((address, self.port))
                sock.listen(16)
                sock.setblocking(False)
                self._sockets.append(sock)
            except OSError:
                continue
        thread = threading.Thread(target=self._tcp_loop, name="dns-tcp", daemon=True)
        thread.start()
        self._threads.append(thread)
        log.info("DNS proxy listening on port %d", self.port)

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()

    # -- loops --------------------------------------------------------------

    def _udp_loop(self) -> None:
        udp_sockets = [s for s in self._sockets if s.type == socket.SOCK_DGRAM]
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select(udp_sockets, [], [], 0.5)
            except (OSError, ValueError):
                return
            for sock in ready:
                try:
                    data, addr = sock.recvfrom(65535)
                except OSError:
                    continue
                response = self.handle(data)
                if response:
                    try:
                        sock.sendto(response, addr)
                    except OSError:
                        pass

    def _tcp_loop(self) -> None:
        listeners = [s for s in self._sockets if s.type == socket.SOCK_STREAM]
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select(listeners, [], [], 0.5)
            except (OSError, ValueError):
                return
            for listener in ready:
                try:
                    conn, _addr = listener.accept()
                except OSError:
                    continue
                threading.Thread(target=self._tcp_client, args=(conn,), daemon=True).start()

    def _tcp_client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            header = conn.recv(2)
            if len(header) < 2:
                return
            length = struct.unpack("!H", header)[0]
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    return
                data += chunk
            response = self.handle(data)
            if response:
                conn.sendall(struct.pack("!H", len(response)) + response)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # -- logic --------------------------------------------------------------

    def handle(self, query: bytes) -> bytes | None:
        question = parse_question(query)
        if not question:
            return None
        name, qtype, qclass, _end = question
        self.queries += 1

        if self.strip_aaaa and qtype == 28:
            return self._empty_response(query)

        key = (name, qtype, qclass)
        now = time.time()
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                self.cache_hits += 1
                return query[:2] + hit[1][2:]

        try:
            response = self.resolver.query_raw(query)
        except Exception as exc:  # noqa: BLE001
            log.warning("DNS upstream failed for %s: %s", name, exc)
            return self._servfail(query)

        if len(response) >= 12:
            ttl = max(30, min(min_ttl(response), self.cache_ttl))
            with self._cache_lock:
                if len(self._cache) > 8192:
                    self._cache.clear()
                self._cache[key] = (now + ttl, response)
        return response

    @staticmethod
    def _servfail(query: bytes) -> bytes:
        header = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8182, 1, 0, 0, 0)
        return header + query[12:] if len(query) > 12 else header

    @staticmethod
    def _empty_response(query: bytes) -> bytes:
        header = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8180, 1, 0, 0, 0)
        return header + query[12:]
