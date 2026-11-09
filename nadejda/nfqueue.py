"""NFQUEUE client implemented directly on top of the netfilter netlink protocol.

This module deliberately has no dependency on libnetfilter_queue: everything is
done with the kernel's NETLINK_NETFILTER socket, which keeps Nadejda a
self-contained, pure-stdlib application.

Protocol reference: include/uapi/linux/netfilter/nfnetlink_queue.h
"""

from __future__ import annotations

import errno
import logging
import os
import select
import socket
import struct

log = logging.getLogger(__name__)

# --- constants -------------------------------------------------------------

NETLINK_NETFILTER = 12
NFNL_SUBSYS_QUEUE = 3

NFQNL_MSG_PACKET = 0
NFQNL_MSG_VERDICT = 1
NFQNL_MSG_CONFIG = 2

NFQA_PACKET_HDR = 1
NFQA_VERDICT_HDR = 2
NFQA_PAYLOAD = 10

NFQA_CFG_CMD = 1
NFQA_CFG_PARAMS = 2
NFQA_CFG_QUEUE_MAXLEN = 3
NFQA_CFG_MASK = 4
NFQA_CFG_FLAGS = 5

NFQA_CFG_F_FAIL_OPEN = 1 << 0

NFQNL_CFG_CMD_BIND = 1
NFQNL_CFG_CMD_UNBIND = 2

NFQNL_COPY_NONE = 0
NFQNL_COPY_META = 1
NFQNL_COPY_PACKET = 2

NF_DROP = 0
NF_ACCEPT = 1
NF_STOLEN = 2
NF_QUEUE = 3
NF_REPEAT = 4
NF_STOP = 5

NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04

NLMSG_ERROR = 2
NLMSG_DONE = 3

NLA_ALIGNTO = 4
NLMSG_ALIGNTO = 4


def _align(n: int, a: int = 4) -> int:
    return (n + a - 1) & ~(a - 1)


def _nla(attr_type: int, data: bytes) -> bytes:
    length = 4 + len(data)
    return struct.pack("=HH", length, attr_type) + data + b"\0" * (_align(length) - length)


def _nfgen(family: int = 0, version: int = 0, res_id: int = 0) -> bytes:
    return struct.pack("!BBH", family, version, res_id)


def _msg(msg_type: int, flags: int, seq: int, payload: bytes) -> bytes:
    length = 16 + len(payload)
    return struct.pack("=IHHII", length, msg_type, flags, seq, 0) + payload


def _parse_attrs(data: bytes, offset: int) -> dict[int, bytes]:
    attrs: dict[int, bytes] = {}
    while offset + 4 <= len(data):
        length, attr_type = struct.unpack("=HH", data[offset : offset + 4])
        if length < 4:
            break
        attrs[attr_type] = data[offset + 4 : offset + length]
        offset += _align(length)
    return attrs


class NFQueueError(RuntimeError):
    pass


class NFQueue:
    """A single netfilter queue attached to the OUTPUT hook."""

    def __init__(self, queue_num: int, *, maxlen: int = 4096, fail_open: bool = True):
        self.queue_num = queue_num
        self.maxlen = maxlen
        self.fail_open = fail_open
        self.sock: socket.socket | None = None
        self._seq = int.from_bytes(os.urandom(2), "big")
        self._bound = False
        self._wake_r: socket.socket | None = None
        self._wake_w: socket.socket | None = None
        self.packets = 0
        self.errors = 0

    # -- low level ----------------------------------------------------------

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return self._seq

    def _request(self, msg_type: int, body: bytes, timeout: float = 5.0) -> None:
        """Send a config message and wait for its ACK/error."""
        assert self.sock is not None
        seq = self._next_seq()
        self.sock.sendto(_msg((NFNL_SUBSYS_QUEUE << 8) | msg_type, NLM_F_REQUEST | NLM_F_ACK, seq, body), (0, 0))
        self.sock.settimeout(timeout)
        try:
            while True:
                data = self.sock.recv(65536)
                off = 0
                while off + 16 <= len(data):
                    length, mtype, _flags, mseq, _pid = struct.unpack("=IHHII", data[off : off + 16])
                    if length < 16 or off + length > len(data):
                        break
                    msg = data[off : off + length]
                    off += _align(length)
                    if mseq != seq:
                        # A packet can arrive while we are (un)binding. Never
                        # leave the kernel waiting for its verdict.
                        if (mtype >> 8) == NFNL_SUBSYS_QUEUE and (mtype & 0xFF) == NFQNL_MSG_PACKET:
                            attrs = _parse_attrs(msg, 20)
                            hdr = attrs.get(NFQA_PACKET_HDR)
                            if hdr is not None and len(hdr) >= 4:
                                self.verdict(struct.unpack("!I", hdr[:4])[0], NF_ACCEPT)
                        continue
                    if mtype == NLMSG_ERROR:
                        err = struct.unpack("=i", msg[16:20])[0]
                        if err == 0:
                            return
                        raise NFQueueError(
                            f"netlink error for {msg_type}: {os.strerror(-err)} ({-err})"
                        )
                    if mtype == NLMSG_DONE:
                        return
        finally:
            self.sock.settimeout(None)

    # -- public API ---------------------------------------------------------

    def open(self) -> None:
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        self.sock.bind((0, 0))
        self._wake_r, self._wake_w = socket.socketpair()

    def bind(self) -> None:
        """Bind to the queue number, ask for full packets and fail-open mode."""
        body = _nfgen(0, 0, self.queue_num) + _nla(NFQA_CFG_CMD, struct.pack("!BBH", NFQNL_CFG_CMD_BIND, 0, 0))
        self._request(NFQNL_MSG_CONFIG, body)

        params = struct.pack("=IB", 0xFFFF, NFQNL_COPY_PACKET)
        body = (
            _nfgen(0, 0, self.queue_num)
            + _nla(NFQA_CFG_PARAMS, params)
            + _nla(NFQA_CFG_QUEUE_MAXLEN, struct.pack("=I", self.maxlen))
        )
        self._request(NFQNL_MSG_CONFIG, body)

        if self.fail_open:
            flags = NFQA_CFG_F_FAIL_OPEN
            body = (
                _nfgen(0, 0, self.queue_num)
                + _nla(NFQA_CFG_MASK, struct.pack("=I", flags))
                + _nla(NFQA_CFG_FLAGS, struct.pack("=I", flags))
            )
            try:
                self._request(NFQNL_MSG_CONFIG, body)
            except NFQueueError as exc:  # older kernels: not fatal
                log.debug("fail-open not supported: %s", exc)
        self._bound = True
        log.info("NFQUEUE %d bound (fail-open=%s, maxlen=%d)", self.queue_num, self.fail_open, self.maxlen)

    def verdict(self, packet_id: int, verdict: int) -> None:
        assert self.sock is not None
        body = _nfgen(0, 0, self.queue_num) + _nla(
            NFQA_VERDICT_HDR, struct.pack("!II", verdict, packet_id)
        )
        seq = self._next_seq()
        self.sock.sendto(
            _msg((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT, NLM_F_REQUEST, seq, body), (0, 0)
        )

    def run(self, handler, stop_event=None) -> None:
        """Receive packets and call ``handler(payload_bytes) -> verdict``.

        The handler must be fast: it runs on the packet processing thread.
        """
        assert self.sock is not None and self._wake_r is not None
        while not (stop_event and stop_event.is_set()):
            try:
                ready, _, _ = select.select([self.sock, self._wake_r], [], [], 1.0)
            except InterruptedError:
                continue
            if self._wake_r in ready:
                try:
                    self._wake_r.recv(64)
                except OSError:
                    pass
                if stop_event and stop_event.is_set():
                    break
            if self.sock not in ready:
                continue
            try:
                data = self.sock.recv(1 << 18)
            except OSError as exc:
                if exc.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EINTR):
                    self.errors += 1
                    continue
                raise
            self._process(data, handler, stop_event)

    def _process(self, data: bytes, handler, stop_event) -> None:
        off = 0
        while off + 16 <= len(data):
            length, mtype, _flags, _seq, _pid = struct.unpack("=IHHII", data[off : off + 16])
            if length < 16 or off + length > len(data):
                break
            msg = data[off : off + length]
            off += _align(length)
            if (mtype >> 8) != NFNL_SUBSYS_QUEUE:
                continue
            if (mtype & 0xFF) != NFQNL_MSG_PACKET:
                if (mtype & 0xFF) == NLMSG_ERROR:
                    self.errors += 1
                continue
            attrs = _parse_attrs(msg, 16 + 4)
            hdr = attrs.get(NFQA_PACKET_HDR)
            payload = attrs.get(NFQA_PAYLOAD)
            if hdr is None or payload is None or len(hdr) < 4:
                continue
            packet_id = struct.unpack("!I", hdr[:4])[0]
            self.packets += 1
            try:
                verdict = handler(payload)
            except Exception:  # never leave the kernel waiting
                log.exception("packet handler failed")
                verdict = NF_ACCEPT
            if verdict is not None:
                self.verdict(packet_id, verdict)
            if stop_event and stop_event.is_set():
                return

    def wake(self) -> None:
        if self._wake_w is not None:
            try:
                self._wake_w.send(b"x")
            except OSError:
                pass

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            if self._bound:
                body = _nfgen(0, 0, self.queue_num) + _nla(
                    NFQA_CFG_CMD, bytes([NFQNL_CFG_CMD_UNBIND])
                )
                self._request(NFQNL_MSG_CONFIG, body, timeout=1.0)
        except Exception:
            pass
        if self._wake_w:
            try:
                self._wake_w.send(b"x")
            except OSError:
                pass
        try:
            self.sock.close()
        finally:
            self.sock = None
            self._bound = False
        for s in (self._wake_r, self._wake_w):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        self._wake_r = self._wake_w = None
