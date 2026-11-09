#!/usr/bin/env python3
"""Smoke test for the pure-python NFQUEUE client.

Run it through ``unshare -Urn`` (see ``make test-netns``), it needs a private
network namespace to create nftables rules and raw sockets without root.
"""
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nadejda.nfqueue import NFQueue, NF_ACCEPT  # noqa: E402


def sh(cmd):
    return subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True).stdout


def main():
    sh("ip link set lo up")
    sh("nft add table inet nadejda_test")
    sh('nft add chain inet nadejda_test out "{ type filter hook output priority -150; policy accept; }"')
    sh("nft add rule inet nadejda_test out tcp dport 8080 queue num 9 bypass")

    seen = []
    stop = threading.Event()

    def handler(data):
        seen.append(data)
        return NF_ACCEPT

    q = NFQueue(9)
    q.open()
    q.bind()
    thread = threading.Thread(target=q.run, args=(handler, stop), daemon=True)
    thread.start()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8080))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        data = conn.recv(100)
        conn.sendall(b"world:" + data)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    client = socket.create_connection(("127.0.0.1", 8080), timeout=5)
    client.sendall(b"hello")
    reply = client.recv(100)
    client.close()
    assert reply == b"world:hello", reply

    deadline = time.time() + 2
    while q.packets == 0 and time.time() < deadline:
        time.sleep(0.05)
    stop.set()
    q.close()
    print(f"queue packets={q.packets} captured={len(seen)}")
    assert q.packets > 0, "no packets reached the queue"
    print("OK")


if __name__ == "__main__":
    main()
