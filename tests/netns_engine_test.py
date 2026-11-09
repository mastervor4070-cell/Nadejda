#!/usr/bin/env python3
"""End-to-end test of the desync engine inside an isolated network namespace.

Topology:

    [ client + Nadejda ]  veth0 10.9.0.1  <---->  veth1 10.9.0.2 [ server ]

The client runs the real nftables/NFQUEUE/raw-socket pipeline, the server is in
a separate network namespace.  A packet sniffer on veth0 records what the
"DPI" would see.

Run:  sudo unshare -Urn python3 tests/netns_engine_test.py
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nadejda.config import Config, GeneralConfig  # noqa: E402
from nadejda.desync import PRESETS, UDP_PRESETS  # noqa: E402
from nadejda.engine import Engine  # noqa: E402
from nadejda.packet import make_fake_client_hello  # noqa: E402

# A real ClientHello from the local TLS stack is ~1.5 KB, i.e. larger than the
# veth MSS.  Depending on TSO/GSO the kernel may hand the queue either one big
# skb or two TCP segments.  The engine deliberately leaves an incomplete
# ClientHello alone, so use a compact but valid hello to exercise the desync
# path deterministically.
PAYLOAD = make_fake_client_hello("www.youtube.com", target_len=900)
SERVER_IP = "10.9.0.2"
CLIENT_IP = "10.9.0.1"


def sh(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True).stdout


# ---------------------------------------------------------------------------
# server side (child network namespace)
# ---------------------------------------------------------------------------


def udp_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SERVER_IP, 443))
    srv.settimeout(60)
    try:
        for _ in range(8):
            data, addr = srv.recvfrom(65535)
            srv.sendto(hashlib.sha256(data).hexdigest().encode(), addr)
    except socket.timeout:
        pass
    finally:
        srv.close()


def server_main() -> None:
    udp_thread = threading.Thread(target=udp_server, daemon=True)
    udp_thread.start()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SERVER_IP, 443))
    srv.listen(8)
    srv.settimeout(60)
    for _ in range(8):
        conn, _ = srv.accept()
        conn.settimeout(15)
        data = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data.extend(chunk)
        conn.sendall(hashlib.sha256(bytes(data)).hexdigest().encode())
        conn.close()
    srv.close()


def spawn_server() -> int:
    r1, w1 = os.pipe()
    r2, w2 = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(w1)
            os.close(r2)
            os.unshare(os.CLONE_NEWNET)
            os.write(w2, b"ready")
            os.read(r1, 1)
            subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
            subprocess.run(["ip", "addr", "add", f"{SERVER_IP}/24", "dev", "veth1"], check=True)
            subprocess.run(["ip", "link", "set", "veth1", "up"], check=True)
            server_main()
        finally:
            os._exit(0)
    os.close(r1)
    os.close(w2)
    assert os.read(r2, 5) == b"ready"
    subprocess.run(["ip", "link", "set", "veth1", "netns", str(pid)], check=True)
    os.write(w1, b"x")
    os.close(w1)
    return pid


# ---------------------------------------------------------------------------
# sniffer
# ---------------------------------------------------------------------------


class Sniffer:
    def __init__(self, iface: str = "veth0"):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.2)
        self.packets: list[dict] = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                raw, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if addr[2] != 4:  # PACKET_OUTGOING only
                continue
            info = self._parse(raw)
            if info:
                self.packets.append(info)

    @staticmethod
    def _parse(raw: bytes) -> dict | None:
        if len(raw) < 34:
            return None
        ethertype = struct.unpack("!H", raw[12:14])[0]
        if ethertype != 0x0800:
            return None
        ip = raw[14:]
        if ip[0] >> 4 != 4:
            return None
        ihl = (ip[0] & 0xF) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        ttl = ip[8]
        proto = ip[9]
        frag = struct.unpack("!H", ip[6:8])[0]
        ip_id = struct.unpack("!H", ip[4:6])[0]
        l4 = ip[ihl:total]
        base = {
            "ttl": ttl,
            "frag": frag,
            "proto": proto,
            "ip_id": ip_id,
            "sport": None,
            "dport": None,
            "seq": 0,
            "flags": 0,
            "payload": b"",
            "length": len(l4),
        }
        if proto == 6:
            if len(l4) < 20:
                return None
            sport, dport, seq = struct.unpack("!HHI", l4[:8])
            offset = (l4[12] >> 4) * 4
            base.update(
                sport=sport,
                dport=dport,
                seq=seq,
                flags=l4[13],
                payload=l4[offset:],
                length=len(l4) - offset,
            )
            return base
        if proto == 17:
            if frag & 0x1FFF:  # continuation fragment: no UDP header here
                base["payload"] = l4
                return base
            if len(l4) < 8:
                return None
            sport, dport, ulen = struct.unpack("!HHH", l4[:6])
            base.update(
                sport=sport,
                dport=dport,
                payload=l4,
                length=max(0, ulen - 8),
            )
            return base
        return None

    def stop(self):
        self._stop.set()


# ---------------------------------------------------------------------------


def make_config(strategy: str, *, quic: str = "off", udp: str = "quic_frag") -> Config:
    general = GeneralConfig(
        queue_num=42,
        scope="all",
        sni_filter=True,
        quic=quic,
        block_quic="off",
        dns=False,
        refresh_seconds=3600,
    )
    udp_cfg = UDP_PRESETS[udp].clone()
    if quic == "desync":
        # Do not try to resolve YouTube domains in the isolated namespace.
        udp_cfg.force_tcp_domains = []
    return Config(
        general=general,
        strategy=PRESETS[strategy].clone(),
        domains=["youtube.com", "googlevideo.com"],
        path=None,  # type: ignore[arg-type]
        udp=udp_cfg,
    )


def run_case(name: str, strategy: str, sni_host: str, checks) -> int:
    payload = (
        PAYLOAD if sni_host == "www.youtube.com" else make_fake_client_hello(sni_host, target_len=900)
    )
    cfg = make_config(strategy)
    engine = Engine(cfg)
    sniffer = Sniffer()
    sniffer.start()
    failures = 0
    try:
        engine.start()
        time.sleep(0.3)

        client = socket.create_connection((SERVER_IP, 443), timeout=8)
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        client.settimeout(8)
        reply = client.recv(64)
        client.close()
        time.sleep(0.3)
        expected_hash = hashlib.sha256(payload).hexdigest().encode()
        if reply != expected_hash:
            print(f"  [{name}] server byte-stream mismatch: {reply!r}")
            failures += 1
        stats = []
        for check in checks:
            ok, detail = check(sniffer.packets)
            stats.append(detail)
            if not ok:
                print(f"  [{name}] check failed: {detail}")
                failures += 1
        print(f"  [{name}] " + "; ".join(stats))
    except Exception as exc:  # noqa: BLE001
        failures += 1
        import traceback

        traceback.print_exc()
        print(f"  [{name}] EXCEPTION {exc}")
    finally:
        engine.shutdown()
        sniffer.stop()
        time.sleep(0.1)
    return failures


def data_segments(packets, dport=443):
    seen = set()
    result = []
    for p in packets:
        if p["dport"] != dport or p["length"] <= 0:
            continue
        key = (p["seq"], p["length"], p["ttl"])
        if key in seen:
            continue
        seen.add(key)
        result.append(p)
    return result


def check_split(packets):
    segs = data_segments(packets)
    # zapret's multisplit sends the overlap segment (568 decoy bytes + the
    # first real byte) first, then the remainder of the ClientHello.
    heads = [s for s in segs if s["length"] == 569]
    return bool(heads), f"tcp data segments={len(segs)} lens={[s['length'] for s in segs][:6]}"


def check_overlap(packets):
    segs = data_segments(packets)
    syn = [p for p in packets if p["dport"] == 443 and p["flags"] & 0x02]
    if not syn:
        return False, "no SYN captured"
    first_data_seq = (syn[0]["seq"] + 1) & 0xFFFFFFFF
    expected = (first_data_seq - 568) & 0xFFFFFFFF
    hit = any(s["seq"] == expected for s in segs)
    return hit, f"overlap segment seq={hex(expected)} found={hit} seqs={[hex(s['seq']) for s in segs][:4]}"


def check_fake(packets):
    fakes = [p for p in packets if p["dport"] == 443 and p["ttl"] <= 4 and p["length"] > 100]
    detail = [(p["ttl"], p["length"]) for p in packets if p["dport"] == 443][:12]
    return bool(fakes), f"low-ttl decoys={len(fakes)} captured={detail}"


def check_no_desync(packets):
    segs = [s for s in data_segments(packets) if s["length"] > 200]
    syn = [p for p in packets if p["dport"] == 443 and p["flags"] & 0x02]
    overlap = False
    if syn:
        expected = (syn[0]["seq"] + 1 - 568) & 0xFFFFFFFF
        overlap = any(s["seq"] == expected for s in data_segments(packets))
    detail = [(s["length"], hex(s["seq"])) for s in data_segments(packets)]
    return len(segs) == 1 and not overlap, f"large data segments={len(segs)} overlap={overlap} all={detail}"


def check_fragments(packets):
    frags = [p for p in packets if p["frag"] & 0x3FFF]
    return len(frags) >= 2, f"ip fragments={len(frags)}"


def make_quic_initial(size: int = 1200) -> bytes:
    """A syntactically valid QUIC v1 Initial long header (payload is opaque)."""
    dcid = bytes(range(8))
    body_len = size - 18
    header = (
        bytes([0xC0])
        + struct.pack("!I", 1)
        + bytes([len(dcid)])
        + dcid
        + b"\x00"  # SCID length
        + b"\x00"  # token length
        + bytes([0x40 | (body_len >> 8), body_len & 0xFF])
    )
    return header + b"\x00" * body_len


def reassemble_udp(packets, *, sport):
    """Reassemble IPv4 fragments of the client's UDP datagram."""
    ids = {p["ip_id"] for p in packets if p["proto"] == 17 and p["sport"] == sport}
    groups: dict[int, list[dict]] = {}
    for p in packets:
        if p["proto"] != 17 or p["ip_id"] not in ids:
            continue
        groups.setdefault(p["ip_id"], []).append(p)
    for frags in groups.values():
        if len(frags) < 2:
            continue
        chunks = {(p["frag"] & 0x1FFF) * 8: p["payload"] for p in frags}
        data = b"".join(chunks[k] for k in sorted(chunks))
        return frags, chunks, data
    return [], {}, b""


def check_udp_fragments(packets, sport, split, original):
    frags, chunks, data = reassemble_udp(packets, sport=sport)
    first_len = len(chunks.get(0, b""))
    expected_first = 8 + split
    ok = (
        len(frags) >= 2
        and first_len == expected_first
        and data[8:] == original
    )
    return ok, (
        f"udp fragments={len(frags)} first_l4={first_len} "
        f"expected={expected_first} payload_ok={data[8:] == original}"
    )


def run_udp_passthrough(name: str) -> int:
    payload = b"\x40" + bytes(range(256)) * 5  # short-header QUIC / RTP-like
    cfg = make_config("seqovl568", quic="desync", udp="quic_frag")
    engine = Engine(cfg)
    sniffer = Sniffer()
    sniffer.start()
    failures = 0
    try:
        engine.start()
        time.sleep(0.3)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(8)
        client.sendto(payload, (SERVER_IP, 443))
        sport = client.getsockname()[1]
        reply = client.recv(64)
        client.close()
        time.sleep(0.3)
        if reply != hashlib.sha256(payload).hexdigest().encode():
            print(f"  [{name}] UDP server saw different bytes: {reply!r}")
            failures += 1
        udp_packets = [
            p for p in sniffer.packets if p["proto"] == 17 and p["sport"] == sport
        ]
        fragmented = any(p["frag"] & 0x3FFF for p in udp_packets)
        ok = len(udp_packets) == 1 and not fragmented
        if not ok:
            print(f"  [{name}] expected one untouched datagram, got {len(udp_packets)}")
            failures += 1
        print(f"  [{name}] datagrams={len(udp_packets)} fragmented={fragmented}")
    except Exception as exc:  # noqa: BLE001
        failures += 1
        import traceback

        traceback.print_exc()
        print(f"  [{name}] EXCEPTION {exc}")
    finally:
        engine.shutdown()
        sniffer.stop()
        time.sleep(0.1)
    return failures


def run_udp_case(name: str, strategy: str, split: int) -> int:
    payload = make_quic_initial()
    cfg = make_config("seqovl568", quic="desync", udp=strategy)
    engine = Engine(cfg)
    sniffer = Sniffer()
    sniffer.start()
    failures = 0
    try:
        engine.start()
        time.sleep(0.3)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(8)
        client.sendto(payload, (SERVER_IP, 443))
        sport = client.getsockname()[1]
        reply = client.recv(64)
        client.close()
        time.sleep(0.3)
        if reply != hashlib.sha256(payload).hexdigest().encode():
            print(f"  [{name}] UDP server saw different bytes: {reply!r}")
            failures += 1
        ok, detail = check_udp_fragments(sniffer.packets, sport, split, payload)
        if not ok:
            print(f"  [{name}] check failed: {detail}")
            failures += 1
        print(f"  [{name}] {detail}")
    except Exception as exc:  # noqa: BLE001
        failures += 1
        import traceback

        traceback.print_exc()
        print(f"  [{name}] EXCEPTION {exc}")
    finally:
        engine.shutdown()
        sniffer.stop()
        time.sleep(0.1)
    return failures


def main() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    sh("ip link set lo up")
    sh("ip link add veth0 type veth peer name veth1")
    sh(f"ip addr add {CLIENT_IP}/24 dev veth0")
    sh("ip link set veth0 up")
    pid = spawn_server()
    failures = 0
    try:
        print("case 1: seqovl568")
        failures += run_case("seqovl568", "seqovl568", "www.youtube.com", [check_split, check_overlap])
        print("case 2: fake_seqovl")
        failures += run_case("fake_seqovl", "fake_seqovl", "www.youtube.com", [check_fake, check_overlap])
        print("case 3: non-listed SNI must pass untouched")
        failures += run_case("passthrough", "seqovl568", "example.com", [check_no_desync])
        print("case 4: ip fragmentation")
        failures += run_case("frag", "frag", "www.youtube.com", [check_fragments])
        print("case 5: QUIC fragmentation")
        failures += run_udp_case("quic_frag", "quic_frag", 64)
        print("case 6: QUIC early split")
        failures += run_udp_case("quic_frag_early", "quic_frag_early", 32)
        print("case 7: non-QUIC UDP must pass untouched")
        failures += run_udp_passthrough("udp_passthrough")
    finally:
        try:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        except OSError:
            pass
    print("FAILURES:", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
