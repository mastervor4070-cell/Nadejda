"""Packet parsing/building helpers: IPv4/IPv6 + TCP, checksums, TLS ClientHello.

Only the small subset needed for DPI desynchronisation is implemented, but it
is written so that every byte we put on the wire is a valid IP/TCP packet.
"""

from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass

PROTO_TCP = 6
PROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01

_IP_ID = 0x4000


def next_ip_id() -> int:
    global _IP_ID
    _IP_ID = (_IP_ID + 1) & 0xFFFF
    return _IP_ID


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass(slots=True)
class Packet:
    raw: bytes
    version: int
    src: str
    dst: str
    src_raw: bytes
    dst_raw: bytes
    ttl: int
    tos: int
    ip_id: int
    frag_off: int
    more_frags: bool
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    urg: int
    options: bytes
    payload: bytes

    @property
    def flow(self) -> tuple[str, int, str, int]:
        return (self.src, self.sport, self.dst, self.dport)

    @property
    def tcp_header_len(self) -> int:
        return 20 + len(self.options)


@dataclass(slots=True)
class UDPPacket:
    """A locally generated UDP datagram as seen on the OUTPUT hook."""

    raw: bytes
    version: int
    src: str
    dst: str
    src_raw: bytes
    dst_raw: bytes
    ttl: int
    tos: int
    ip_id: int
    sport: int
    dport: int
    payload: bytes

    @property
    def flow(self) -> tuple[str, int, str, int]:
        return (self.src, self.sport, self.dst, self.dport)


def parse_packet(data: bytes) -> Packet | None:
    """Parse an IPv4/IPv6 TCP packet. Returns None for anything else."""
    if len(data) < 40:
        return None
    version = data[0] >> 4
    if version == 4:
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl + 20:
            return None
        total_len = struct.unpack("!H", data[2:4])[0]
        if total_len < ihl + 20:
            return None
        frag = struct.unpack("!H", data[6:8])[0]
        frag_off = frag & 0x1FFF
        more = bool(frag & 0x2000)
        if frag_off != 0:  # continuation of a fragmented datagram
            return None
        proto = data[9]
        if proto != PROTO_TCP:
            return None
        src_raw = data[12:16]
        dst_raw = data[16:20]
        src, dst = socket.inet_ntoa(src_raw), socket.inet_ntoa(dst_raw)
        ttl, tos = data[8], data[1]
        ip_id = struct.unpack("!H", data[4:6])[0]
        l4 = data[ihl:total_len]
    elif version == 6:
        if len(data) < 60:
            return None
        payload_len = struct.unpack("!H", data[4:6])[0]
        nxt = data[6]
        if nxt != PROTO_TCP:
            return None
        src_raw, dst_raw = data[8:24], data[24:40]
        src, dst = socket.inet_ntop(socket.AF_INET6, src_raw), socket.inet_ntop(socket.AF_INET6, dst_raw)
        ttl, tos = data[7], (data[0] & 0x0F) << 4 | (data[1] >> 4)
        ip_id, frag_off, more = 0, 0, False
        l4 = data[40 : 40 + payload_len]
    else:
        return None

    if len(l4) < 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", l4[:12])
    offset = (l4[12] >> 4) * 4
    if offset < 20 or len(l4) < offset:
        return None
    flags = l4[13]
    window = struct.unpack("!H", l4[14:16])[0]
    urg = struct.unpack("!H", l4[18:20])[0]
    options = l4[20:offset]
    return Packet(
        raw=data,
        version=version,
        src=src,
        dst=dst,
        src_raw=src_raw,
        dst_raw=dst_raw,
        ttl=ttl,
        tos=tos,
        ip_id=ip_id,
        frag_off=frag_off,
        more_frags=more,
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
        urg=urg,
        options=options,
        payload=l4[offset:],
    )


def parse_udp_packet(data: bytes) -> UDPPacket | None:
    """Parse a complete (not yet fragmented) IPv4/IPv6 UDP datagram.

    The OUTPUT hook sees locally generated datagrams before the kernel splits
    them, so ``frag_off``/MF must be clear.  Anything already fragmented is
    left untouched: re-fragmenting a fragment is a recipe for corruption.
    """
    if len(data) < 28:
        return None
    version = data[0] >> 4
    if version == 4:
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl + 8:
            return None
        total_len = struct.unpack("!H", data[2:4])[0]
        if total_len < ihl + 8 or total_len > len(data):
            return None
        frag = struct.unpack("!H", data[6:8])[0]
        if frag & 0x3FFF:  # MF or a non-zero fragment offset
            return None
        if data[9] != PROTO_UDP:
            return None
        src_raw, dst_raw = data[12:16], data[16:20]
        src, dst = socket.inet_ntoa(src_raw), socket.inet_ntoa(dst_raw)
        ttl, tos = data[8], data[1]
        ip_id = struct.unpack("!H", data[4:6])[0]
        l4 = data[ihl:total_len]
    elif version == 6:
        if len(data) < 48:
            return None
        payload_len = struct.unpack("!H", data[4:6])[0]
        if data[6] != PROTO_UDP or payload_len < 8 or 40 + payload_len > len(data):
            return None
        src_raw, dst_raw = data[8:24], data[24:40]
        src, dst = socket.inet_ntop(socket.AF_INET6, src_raw), socket.inet_ntop(socket.AF_INET6, dst_raw)
        ttl, tos = data[7], 0
        ip_id = 0
        l4 = data[40 : 40 + payload_len]
    else:
        return None

    if len(l4) < 8:
        return None
    sport, dport, udp_len, _csum = struct.unpack("!HHHH", l4[:8])
    if udp_len < 8 or udp_len > len(l4):
        return None
    return UDPPacket(
        raw=data[: (ihl if version == 4 else 40) + udp_len],
        version=version,
        src=src,
        dst=dst,
        src_raw=src_raw,
        dst_raw=dst_raw,
        ttl=ttl,
        tos=tos,
        ip_id=ip_id,
        sport=sport,
        dport=dport,
        payload=l4[8:udp_len],
    )


# --------------------------------------------------------------------------
# building
# --------------------------------------------------------------------------


def _tcp_segment(
    pkt: Packet,
    seq: int,
    payload: bytes,
    *,
    flags: int | None = None,
    badsum: bool = False,
) -> bytes:
    flags = pkt.flags if flags is None else flags
    offset = (20 + len(pkt.options)) // 4
    header = struct.pack(
        "!HHIIBBHHH",
        pkt.sport,
        pkt.dport,
        seq & 0xFFFFFFFF,
        pkt.ack,
        (offset << 4) | 0,
        flags,
        pkt.window,
        0,
        pkt.urg,
    ) + pkt.options
    segment = header + payload
    if pkt.version == 4:
        pseudo = pkt.src_raw + pkt.dst_raw + struct.pack("!BBH", 0, PROTO_TCP, len(segment))
    else:
        pseudo = pkt.src_raw + pkt.dst_raw + struct.pack("!I3xB", len(segment), PROTO_TCP)
    csum = checksum(pseudo + segment)
    if badsum:
        csum ^= 0xFFFF
        if csum == 0:
            csum = 0xDEAD
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def _ip_header(
    pkt: Packet,
    payload_len: int,
    *,
    ttl: int,
    ip_id: int,
    mf: bool = False,
    offset: int = 0,
    proto: int = PROTO_TCP,
) -> bytes:
    if pkt.version == 4:
        total = 20 + payload_len
        frag = (0x2000 if mf else 0) | (offset & 0x1FFF)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            pkt.tos,
            total,
            ip_id & 0xFFFF,
            frag,
            ttl,
            proto,
            0,
            pkt.src_raw,
            pkt.dst_raw,
        )
        csum = checksum(header)
        return header[:10] + struct.pack("!H", csum) + header[12:]
    # IPv6 (plain, non-fragmented TCP path; UDP fragmentation uses its own
    # fragment-header builder below).
    return struct.pack("!IHBB16s16s", 0x60000000, payload_len, proto, ttl, pkt.src_raw, pkt.dst_raw)


def build_segment(
    pkt: Packet,
    seq: int,
    payload: bytes,
    *,
    flags: int | None = None,
    ttl: int | None = None,
    ip_id: int | None = None,
    badsum: bool = False,
) -> bytes:
    segment = _tcp_segment(pkt, seq, payload, flags=flags, badsum=badsum)
    header = _ip_header(
        pkt,
        len(segment),
        ttl=pkt.ttl if ttl is None else ttl,
        ip_id=next_ip_id() if ip_id is None else ip_id,
    )
    return header + segment


def build_reset(pkt: Packet) -> bytes:
    """Build a RST+ACK that looks like it came from the peer.

    ``pkt`` is a client-to-server packet.  Its ACK field is exactly the next
    sequence number the client expects from the server, so a reset carrying
    that sequence is accepted by the client's TCP stack and aborts the socket
    immediately.  Used to break flows that the provider has silently
    black-holed, so the application retries on a fresh connection instead of
    hanging for minutes.
    """
    seq = pkt.ack & 0xFFFFFFFF
    ack = (pkt.seq + len(pkt.payload)) & 0xFFFFFFFF
    header = struct.pack(
        "!HHIIBBHHH",
        pkt.dport,
        pkt.sport,
        seq,
        ack,
        (5 << 4),
        TCP_RST | TCP_ACK,
        0,
        0,
        0,
    )
    if pkt.version == 4:
        pseudo = pkt.dst_raw + pkt.src_raw + struct.pack("!BBH", 0, PROTO_TCP, len(header))
    else:
        pseudo = pkt.dst_raw + pkt.src_raw + struct.pack("!I3xB", len(header), PROTO_TCP)
    csum = checksum(pseudo + header)
    segment = header[:16] + struct.pack("!H", csum) + header[18:]

    if pkt.version == 4:
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            pkt.tos,
            20 + len(segment),
            next_ip_id(),
            0,
            64,
            PROTO_TCP,
            0,
            pkt.dst_raw,
            pkt.src_raw,
        )
        csum = checksum(ip)
        ip = ip[:10] + struct.pack("!H", csum) + ip[12:]
        return ip + segment

    return (
        struct.pack(
            "!IHBB16s16s",
            0x60000000,
            len(segment),
            PROTO_TCP,
            64,
            pkt.dst_raw,
            pkt.src_raw,
        )
        + segment
    )


def build_fragments(pkt: Packet, seq: int, payload: bytes, *, flags: int | None = None, split_at: int = 0) -> list[bytes]:
    """Split one TCP segment into two IPv4 fragments (MTU-independent)."""
    if pkt.version != 4:
        return [build_segment(pkt, seq, payload, flags=flags)]
    segment = _tcp_segment(pkt, seq, payload, flags=flags)
    header_len = 20 + len(pkt.options)
    if split_at <= header_len or split_at >= len(segment):
        split_at = header_len + max(8, ((len(segment) - header_len) // 2) // 8 * 8)
    split_at -= (split_at - header_len) % 8
    if split_at <= header_len or split_at >= len(segment):
        return [build_segment(pkt, seq, payload, flags=flags)]
    ip_id = next_ip_id()
    first = _ip_header(pkt, split_at, ttl=pkt.ttl, ip_id=ip_id, mf=True) + segment[:split_at]
    second = _ip_header(
        pkt, len(segment) - split_at, ttl=pkt.ttl, ip_id=ip_id, offset=split_at // 8
    ) + segment[split_at:]
    return [first, second]


# --------------------------------------------------------------------------
# UDP / QUIC
# --------------------------------------------------------------------------


def _varint(buf: bytes, offset: int) -> tuple[int, int]:
    """Read a QUIC variable-length integer (RFC 9000, section 16)."""
    if offset >= len(buf):
        raise ValueError("truncated varint")
    first = buf[offset]
    size = 1 << (first >> 6)
    if offset + size > len(buf):
        raise ValueError("truncated varint")
    value = first & 0x3F
    for index in range(1, size):
        value = (value << 8) | buf[offset + index]
    return value, offset + size


def is_quic_initial(payload: bytes) -> bool:
    """Heuristically recognise a QUIC Initial packet.

    We deliberately do not decrypt the ClientHello: QUIC Initial protection is
    cheap for a DPI to remove as well.  The point is to catch client Initials
    (which carry the TLS SNI) and leave TURN/RTP/datagram traffic alone.
    """
    if len(payload) < 48:
        return False
    first = payload[0]
    if not first & 0x80 or not first & 0x40:  # long header + fixed bit
        return False
    version = payload[1:5]
    if version == b"\0\0\0\0":  # Version Negotiation
        return False
    type_nibble = first & 0xF0
    if version == b"\x6b\x33\x43\xcf":  # QUIC v2: Initial is 0b01
        is_initial = type_nibble == 0xD0
    else:  # QUIC v1 and v1-compatible drafts: Initial is 0b00
        is_initial = type_nibble == 0xC0
    if not is_initial:
        return False
    try:
        offset = 5
        dcid_len = payload[offset]
        offset += 1
        if not 1 <= dcid_len <= 20:
            return False
        offset += dcid_len
        if offset >= len(payload):
            return False
        scid_len = payload[offset]
        offset += 1
        if scid_len > 20:
            return False
        offset += scid_len
        token_len, offset = _varint(payload, offset)
        offset += token_len
        length, offset = _varint(payload, offset)
        if length <= 0:
            return False
        return offset + length <= len(payload)
    except (ValueError, IndexError):
        return False


def _udp_datagram(pkt: UDPPacket, payload: bytes, *, badsum: bool = False) -> bytes:
    """Build a UDP header + payload with a correct (or deliberately bad) checksum."""
    length = 8 + len(payload)
    header = struct.pack("!HHHH", pkt.sport, pkt.dport, length, 0)
    if pkt.version == 4:
        pseudo = pkt.src_raw + pkt.dst_raw + struct.pack("!BBH", 0, PROTO_UDP, length)
    else:
        pseudo = pkt.src_raw + pkt.dst_raw + struct.pack("!I3xB", length, PROTO_UDP)
    csum = checksum(pseudo + header + payload)
    if badsum:
        # A zero checksum would mean "checksum not computed" for IPv4, which
        # the server would happily accept.  Flip it to a guaranteed mismatch.
        csum ^= 0xFFFF
        if csum == 0:
            csum = 0xDEAD
    elif csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", pkt.sport, pkt.dport, length, csum) + payload


def build_udp_datagram(
    pkt: UDPPacket,
    payload: bytes,
    *,
    ttl: int | None = None,
    badsum: bool = False,
    ip_id: int | None = None,
) -> bytes:
    """Wrap ``payload`` into a complete IP+UDP packet for ``pkt``'s flow.

    Used by the fake-UDP strategies: the decoy is sent with a low TTL and/or a
    broken checksum, so the on-path DPI processes it while the real server
    discards it.
    """
    segment = _udp_datagram(pkt, payload, badsum=badsum)
    header = _ip_header(
        pkt,  # type: ignore[arg-type]
        len(segment),
        ttl=pkt.ttl if ttl is None else ttl,
        ip_id=next_ip_id() if ip_id is None else ip_id,
        proto=PROTO_UDP,
    )
    return header + segment


def _ip6_fragment(pkt: UDPPacket, chunk: bytes, offset: int, more: bool, ident: int) -> bytes:
    frag = struct.pack(
        "!BBHI",
        PROTO_UDP,
        0,
        ((offset // 8) << 3) | (1 if more else 0),
        ident & 0xFFFFFFFF,
    )
    payload = frag + chunk
    # Keep version/traffic-class/flow-label from the original datagram.
    first_word = struct.unpack("!I", pkt.raw[:4])[0]
    return struct.pack(
        "!IHBB16s16s",
        first_word,
        len(payload),
        44,  # Fragment extension header
        pkt.ttl,
        pkt.src_raw,
        pkt.dst_raw,
    ) + payload


def build_udp_fragments(
    pkt: UDPPacket,
    split_at: int = 64,
    *,
    disorder: bool = True,
    max_fragment: int = 1400,
) -> list[bytes]:
    """Split one UDP datagram into IP fragments.

    ``split_at`` is a byte offset inside the UDP *payload* (not counting the
    8-byte UDP header).  The first fragment ends there, so a DPI that only
    inspects the first fragment never sees the rest of a QUIC Initial.  The
    endpoint reassembles the datagram transparently.
    """
    payload = pkt.payload
    if len(payload) < 16:
        return []
    datagram = _udp_datagram(pkt, payload)
    l4_len = len(datagram)

    # Fragment offsets are counted in 8-byte units from the start of the IP
    # payload, which includes the 8-byte UDP header.
    split_at = max(8, min(int(split_at), len(payload) - 8))
    split_at -= split_at % 8
    first_len = 8 + split_at
    if first_len <= 8 or first_len >= l4_len:
        return []

    chunks = [datagram[:first_len]]
    rest = datagram[first_len:]
    max_fragment = max(8, (max_fragment // 8) * 8)
    while rest:
        take = min(max_fragment, len(rest))
        if take < len(rest):
            take -= take % 8
            if take <= 0:
                take = max_fragment
        chunks.append(rest[:take])
        rest = rest[take:]

    ip_id = next_ip_id()
    fragments: list[bytes] = []
    offset = 0
    for index, chunk in enumerate(chunks):
        more = index < len(chunks) - 1
        if pkt.version == 4:
            header = _ip_header(
                pkt,  # type: ignore[arg-type]
                len(chunk),
                ttl=pkt.ttl,
                ip_id=ip_id,
                mf=more,
                offset=offset // 8,
                proto=PROTO_UDP,
            )
            fragments.append(header + chunk)
        else:
            fragments.append(_ip6_fragment(pkt, chunk, offset, more, ip_id))
        offset += len(chunk)

    if disorder and len(fragments) > 1:
        fragments.reverse()
    return fragments


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------


@dataclass(slots=True)
class ClientHello:
    sni: str | None
    sni_offset: int | None
    sni_len: int
    extensions_offset: int | None = None
    extensions_len: int = 0


def parse_client_hello(payload: bytes) -> ClientHello | None:
    """Extract the SNI from a TLS ClientHello record at the start of ``payload``."""
    try:
        if len(payload) < 44 or payload[0] != TLS_HANDSHAKE or payload[5] != TLS_CLIENT_HELLO:
            return None
        record_len = struct.unpack("!H", payload[3:5])[0]
        if record_len + 5 > len(payload):
            record_len = len(payload) - 5
        p = 9 + 2 + 32  # handshake header + version + random
        if p >= len(payload):
            return None
        p += 1 + payload[p]  # session id
        if p + 2 > len(payload):
            return None
        p += 2 + struct.unpack("!H", payload[p : p + 2])[0]  # cipher suites
        if p + 1 > len(payload):
            return None
        p += 1 + payload[p]  # compression methods
        if p + 2 > len(payload):
            return None
        ext_total = struct.unpack("!H", payload[p : p + 2])[0]
        ext_start = p + 2
        end = min(len(payload), ext_start + ext_total)
        q = ext_start
        while q + 4 <= end:
            etype, elen = struct.unpack("!HH", payload[q : q + 4])
            q += 4
            if etype == 0:  # server_name
                if q + 2 > end:
                    return None
                list_len = struct.unpack("!H", payload[q : q + 2])[0]
                r = q + 2
                stop = min(end, r + list_len)
                while r + 3 <= stop:
                    ntype = payload[r]
                    nlen = struct.unpack("!H", payload[r + 1 : r + 3])[0]
                    if ntype == 0 and r + 3 + nlen <= stop:
                        name = payload[r + 3 : r + 3 + nlen]
                        return ClientHello(
                            sni=name.decode("ascii", "replace").rstrip("."),
                            sni_offset=r + 3,
                            sni_len=nlen,
                            extensions_offset=ext_start,
                            extensions_len=ext_total,
                        )
                    r += 3 + nlen
                return ClientHello(None, None, 0, ext_start, ext_total)
            q += elen
        return ClientHello(None, None, 0, ext_start, ext_total)
    except (IndexError, ValueError, struct.error):
        return None


def looks_like_client_hello(payload: bytes) -> bool:
    return len(payload) >= 9 and payload[0] == TLS_HANDSHAKE and payload[5] == TLS_CLIENT_HELLO


_hello_cache: dict[str, bytes] = {}


def make_client_hello(sni: str, min_len: int = 700) -> bytes:
    """Generate a real, syntactically valid ClientHello for ``sni``.

    Uses the system TLS stack through a memory BIO, so no hardcoded blob and no
    TLS library of our own is required.
    """
    key = f"{sni}|{min_len}"
    if key in _hello_cache:
        return _hello_cache[key]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    except ssl.SSLError:
        pass
    hello = outgoing.read()
    if len(hello) < min_len:
        hello = _pad_hello(hello, min_len)
    _hello_cache[key] = hello
    return hello


def make_fake_client_hello(sni: str, target_len: int = 512) -> bytes:
    """A small hand-crafted but syntactically valid ClientHello.

    Used as the low-TTL decoy.  Keeping it below the MTU matters: the kernel
    refuses to send an oversized raw IP packet instead of fragmenting it.
    """
    host = sni.encode("ascii", "replace")
    sni_list = struct.pack("!H", 3 + len(host)) + b"\x00" + struct.pack("!H", len(host)) + host
    sni_ext = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list
    exts = sni_ext
    pad = max(0, target_len - 200)
    if pad:
        exts += struct.pack("!HH", 21, pad) + b"\0" * pad
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"  # session id
        + b"\x00\x04\x13\x01\x13\x02"  # cipher suites
        + b"\x01\x00"  # compression
        + struct.pack("!H", len(exts))
        + exts
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _pad_hello(hello: bytes, min_len: int) -> bytes:
    """Append a TLS padding extension (type 21) and fix up the length fields."""
    info = parse_client_hello(hello)
    if not info or info.extensions_offset is None:
        return hello
    pad = min_len - len(hello)
    if pad < 4:
        return hello
    pad -= 4
    ext_start = info.extensions_offset
    ext_end = ext_start + info.extensions_len
    extra = struct.pack("!HH", 21, pad) + b"\0" * pad
    result = bytearray(hello[:ext_end] + extra + hello[ext_end:])
    struct.pack_into("!H", result, ext_start - 2, info.extensions_len + len(extra))
    struct.pack_into("!I", result, 6, len(result) - 9)
    struct.pack_into("!H", result, 3, len(result) - 5)
    return bytes(result)


def split_payload(
    pkt: Packet,
    payload: bytes,
    positions: list[int],
    max_segment: int,
    start_seq: int | None = None,
) -> list[tuple[int, bytes]]:
    """Split ``payload`` at ``positions`` and cap every segment at max_segment."""
    base = pkt.seq if start_seq is None else start_seq
    bounds = sorted({0, *[p for p in positions if 0 < p < len(payload)], len(payload)})
    result: list[tuple[int, bytes]] = []
    for a, b in zip(bounds, bounds[1:]):
        chunk = payload[a:b]
        offset = a
        while chunk:
            piece = chunk[:max_segment]
            result.append(((base + offset) & 0xFFFFFFFF, piece))
            chunk = chunk[len(piece) :]
            offset += len(piece)
    return result
