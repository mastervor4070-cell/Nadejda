"""WinDivert backend for Nadejda.

``pydivert`` is imported lazily: the strategy layer and the test suite work on
Linux without it, and the Windows build only needs it at runtime.

WinDivert semantics worth remembering:

* a non-sniff handle *owns* the packet: if the application does not call
  ``send``, the packet is dropped;
* packets injected through the same handle are not captured again, so the
  engine never loops on its own output;
* ``send(..., recalculate_checksum=False)`` preserves deliberately broken
  checksums used by the ``fake_badsum`` strategies.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger(__name__)


class WinDivertError(RuntimeError):
    """WinDivert is missing, not installed as a driver, or not permitted."""


@dataclass(slots=True)
class CapturedPacket:
    raw: bytes
    interface: tuple[int, int] | None = None
    direction: int = 0
    timestamp: int = 0
    # WinDivert's checksum flags.  An outbound packet may still have an
    # uncomputed checksum (NIC offload); these flags must survive the
    # pass-through re-injection or the packet goes out with a zero checksum.
    ip_checksum: bool = False
    tcp_checksum: bool = False
    udp_checksum: bool = False


def is_admin() -> bool:
    """True when the process can open a WinDivert handle.

    WinDivert needs administrator rights.  On non-Windows platforms this
    returns True so the portable engine can be exercised in tests.
    """
    if os.name != "nt":
        return True
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def pydivert_version() -> str | None:
    try:
        import pydivert

        return getattr(pydivert, "__version__", None) or "unknown"
    except Exception:
        return None


class WinDivertHandle:
    """Minimal, engine-facing wrapper around ``pydivert.Divert``."""

    def __init__(self, filter: str):
        self.filter = filter
        self._divert = None

    @property
    def is_open(self) -> bool:
        return self._divert is not None and bool(getattr(self._divert, "is_open", False))

    def open(self) -> "WinDivertHandle":
        if self.is_open:
            return self
        try:
            import pydivert
            from pydivert.consts import Flag, Layer
        except ImportError as exc:  # pragma: no cover - Windows-only path
            raise WinDivertError(
                "pydivert is not installed; run: pip install pydivert"
            ) from exc
        if os.name == "nt" and not is_admin():
            raise WinDivertError(
                "administrator rights are required; start Nadejda from an "
                "elevated terminal or use the installed scheduled task"
            )
        try:
            divert = pydivert.Divert(
                self.filter,
                layer=Layer.NETWORK,
                priority=0,
                flags=Flag.DEFAULT,
            )
            divert.open()
        except Exception as exc:  # pragma: no cover - Windows-only path
            raise WinDivertError(
                f"cannot open WinDivert with filter {self.filter!r}: {exc}"
            ) from exc
        self._divert = divert
        log.info("WinDivert handle opened (%s)", self.filter)
        return self

    def recv(self, timeout: float | None = 0.5) -> CapturedPacket | None:
        """Return the next captured packet, or None on timeout."""
        if self._divert is None:
            raise RuntimeError("WinDivert handle is not open")
        try:
            packet = self._divert.recv(timeout=timeout)
        except TimeoutError:
            return None
        # pydivert reuses its receive buffer, so copy the bytes before the
        # next recv call overwrites them.
        interface = tuple(packet.interface) if packet.interface else None
        return CapturedPacket(
            raw=bytes(packet.raw),
            interface=interface,
            direction=int(packet.direction),
            timestamp=int(getattr(packet, "timestamp", 0) or 0),
            ip_checksum=bool(packet.ip_checksum),
            tcp_checksum=bool(packet.tcp_checksum),
            udp_checksum=bool(packet.udp_checksum),
        )

    def send(
        self,
        raw: bytes,
        interface: tuple[int, int] | None = None,
        checksums: tuple[bool, bool, bool] | None = None,
    ) -> None:
        """Inject one raw IP packet.

        ``checksums`` carries the WinDivert flags for a packet that was
        captured and is being passed through unchanged.  For packets built by
        the engine the flags default to ``(True, True, True)``: the checksums
        are final, so WinDivert must not rewrite them (fake_badsum decoys rely
        on that).  The bytes themselves are never modified here.
        """
        if self._divert is None:
            raise RuntimeError("WinDivert handle is not open")
        import pydivert
        from pydivert.consts import Direction

        packet = pydivert.Packet(
            raw,
            interface=interface,
            direction=Direction.OUTBOUND,
        )
        ip_ok, tcp_ok, udp_ok = checksums or (True, True, True)
        packet.ip_checksum = ip_ok
        packet.tcp_checksum = tcp_ok
        packet.udp_checksum = udp_ok
        self._divert.send(packet, recalculate_checksum=False)

    def close(self) -> None:
        divert, self._divert = self._divert, None
        if divert is not None:
            try:
                divert.close()
            except Exception:
                pass

    def __enter__(self) -> "WinDivertHandle":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def check_filter(filter: str) -> tuple[bool, str]:
    """Validate a WinDivert filter string without opening a handle."""
    try:
        import pydivert
    except ImportError:
        return False, "pydivert is not installed (pip install pydivert)"
    try:
        ok, position, message = pydivert.Divert.check_filter(filter)
    except Exception as exc:
        return False, f"filter check failed: {exc}"
    if ok:
        return True, "ok"
    return False, f"{message} (at position {position})"
