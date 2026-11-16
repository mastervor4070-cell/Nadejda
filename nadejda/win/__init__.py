"""Nadejda for Windows: WinDivert instead of nftables + NFQUEUE.

The packet planning code (``nadejda.packet`` and ``nadejda.desync``) is
portable, so this package only replaces the plumbing:

    Linux    nftables queues outbound packets -> NFQUEUE -> Engine.handle()
    Windows  WinDivert intercepts outbound packets -> WinEngine.process()

Both produce the same raw IP packets.  On Linux they go out through a marked
raw socket; on Windows WinDivert injects them back into the stack, so no
administrative firewall rules are needed.
"""

from .engine import Decision, WinEngine, build_filter

__all__ = ["Decision", "WinEngine", "build_filter"]
