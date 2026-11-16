"""Command line interface for Nadejda for Windows.

    nadejda-win start     run the engine (needs administrator rights)
    nadejda-win stop      stop the running engine
    nadejda-win status    show counters from the running engine
    nadejda-win test      self-check: filter, strategies, UDP
    nadejda-win doctor    print the environment
    nadejda-win gui       graphical interface (tkinter)
    nadejda-win config    print the configuration path
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from .. import __version__
from .. import config as configmod
from ..desync import PRESETS, UDP_PRESETS
from ..hostlist import HostList
from ..packet import is_quic_initial, make_client_hello, parse_packet
from ..payloads import get as get_payload
from .divert import WinDivertError, check_filter, is_admin, pydivert_version
from .engine import WinEngine, build_filter

log = logging.getLogger("nadejda.win")

ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------


def state_dir() -> Path:
    override = os.environ.get("NADEJDA_STATE")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "Nadejda"
    return Path.home() / ".local" / "state" / "nadejda"


def default_config_path() -> Path:
    override = os.environ.get("NADEJDA_CONFIG")
    if override:
        return Path(override)
    if os.name == "nt":
        return state_dir() / "config.toml"
    return ROOT / "config" / "config.toml"


def bundled_config_path() -> Path | None:
    """Default config shipped inside a PyInstaller executable."""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    candidate = Path(base) / "config" / "config.toml"
    return candidate if candidate.is_file() else None


def ensure_config() -> Path:
    """Return the config path, installing the bundled default if needed.

    The standalone .exe has no installer, so on the first run it copies the
    shipped config to ``%ProgramData%/Nadejda/config.toml``.  The exe is
    elevated (requireAdministrator), so the write is allowed.
    """
    target = default_config_path()
    if target.is_file():
        return target
    bundled = bundled_config_path()
    if bundled is None:
        return target
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(bundled, target)
        log.info("installed default configuration at %s", target)
    except OSError:
        log.warning("cannot create default configuration at %s", target, exc_info=True)
    return target


def _pid_path() -> Path:
    return state_dir() / "nadejda.pid"


def _status_path() -> Path:
    return state_dir() / "status.json"


def _log_path() -> Path:
    return state_dir() / "nadejda.log"


def load_config(path: str | Path | None) -> configmod.Config:
    target = Path(path) if path else ensure_config()
    if not target.is_file():
        raise SystemExit(
            f"config not found: {target}\n"
            "run windows\\install.ps1, or pass --config PATH"
        )
    return configmod.load(target)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return False
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_pid() -> int | None:
    try:
        return int(_pid_path().read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def read_status() -> dict | None:
    try:
        return json.loads(_status_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def running_pid() -> int | None:
    """PID of a running engine, including one started by the GUI.

    The GUI keeps the engine in its own process and does not write a pid file
    (``stop`` must not kill the whole window), so the status file is consulted
    as a fallback.
    """
    pid = read_pid()
    if pid and _pid_alive(pid):
        return pid
    payload = read_status()
    if payload and payload.get("running"):
        pid = payload.get("pid")
        if isinstance(pid, int) and _pid_alive(pid):
            return pid
    return None


# ---------------------------------------------------------------------------
# synthetic packets (used by `test`)
# ---------------------------------------------------------------------------


def tcp_packet(
    payload: bytes, dport: int = 443, seq: int = 1000, sport: int = 50000
) -> bytes:
    src = socket.inet_aton("192.168.1.10")
    dst = socket.inet_aton("93.184.216.34")
    tcp = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, 1, (5 << 4), 0x18, 65535, 0, 0
    ) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        src,
        dst,
    )
    return ip + tcp


def udp_packet(payload: bytes, dport: int = 443, sport: int = 50001) -> bytes:
    src = socket.inet_aton("192.168.1.10")
    dst = socket.inet_aton("93.184.216.34")
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        2,
        0,
        64,
        17,
        0,
        src,
        dst,
    )
    return ip + udp


def _hello_covered(packets: list[bytes], hello: bytes, base_seq: int) -> bool:
    """Every byte of ``hello`` must appear at its offset in some segment."""
    pieces: list[tuple[int, bytes]] = []
    for raw in packets:
        pkt = parse_packet(raw)
        if pkt is None or not pkt.payload:
            continue
        pieces.append((pkt.seq, pkt.payload))
    if not pieces:
        return False
    for index in range(len(hello)):
        wanted = hello[index]
        found = False
        for seq, data in pieces:
            offset = seq - base_seq
            if offset >= 0x80000000:
                offset -= 0x100000000
            pos = index - offset
            if 0 <= pos < len(data) and data[pos] == wanted:
                found = True
                break
        if not found:
            return False
    return True


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_start(args) -> int:
    cfg = load_config(args.config)
    if args.strategy:
        if args.strategy not in PRESETS:
            print(f"unknown strategy: {args.strategy}", file=sys.stderr)
            return 2
        cfg.strategy = PRESETS[args.strategy].clone()
    if args.udp_strategy:
        if args.udp_strategy not in UDP_PRESETS:
            print(f"unknown UDP strategy: {args.udp_strategy}", file=sys.stderr)
            return 2
        cfg.udp = UDP_PRESETS[args.udp_strategy].clone()

    if pydivert_version() is None:
        print(
            "pydivert is not installed.  Run windows\\install.ps1 or:\n"
            "  pip install pydivert",
            file=sys.stderr,
        )
        return 2
    if os.name == "nt" and not is_admin():
        print(
            "Nadejda needs administrator rights to open the WinDivert driver.\n"
            "Start it from an elevated terminal, or use the installed "
            "scheduled task (schtasks /Run /TN Nadejda).",
            file=sys.stderr,
        )
        return 2

    running = running_pid()
    if running:
        print(f"already running (pid {running})", file=sys.stderr)
        return 1

    state = state_dir()
    state.mkdir(parents=True, exist_ok=True)
    _setup_logging(args.log_level)
    engine = WinEngine(cfg, status_path=_status_path())
    _pid_path().write_text(str(os.getpid()), encoding="ascii")

    def _stop(signum, frame):
        log.info("signal %s: stopping", signum)
        engine.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass

    log.info(
        "Nadejda %s for Windows: strategy=%s udp=%s quic=%s",
        __version__,
        cfg.strategy.name,
        cfg.udp.name,
        cfg.general.quic,
    )
    print(f"Nadejda {__version__} for Windows")
    print(f"  config   : {cfg.path}")
    print(f"  strategy : {cfg.strategy.name}")
    print(f"  UDP      : {cfg.udp.name} (QUIC: {cfg.general.quic})")
    print(f"  log      : {_log_path()}")
    print("Press Ctrl+C to stop.")
    try:
        engine.run()
    except WinDivertError as exc:
        log.error("%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        try:
            _pid_path().unlink()
        except OSError:
            pass
        try:
            _status_path().unlink()
        except OSError:
            pass
    return 0


def cmd_stop(args) -> int:
    pid = read_pid()
    if not pid:
        other = running_pid()
        if other:
            print(
                f"engine is running inside another process (pid {other}); "
                "stop it from that window",
                file=sys.stderr,
            )
            return 1
        print("not running (no pid file)")
        return 0
    if not _pid_alive(pid):
        other = running_pid()
        if other and other != pid:
            print(
                f"engine is running inside another process (pid {other}); "
                "stop it from that window",
                file=sys.stderr,
            )
            return 1
        print(f"not running (stale pid {pid})")
        _pid_path().unlink(missing_ok=True)
        _status_path().unlink(missing_ok=True)
        return 0
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            print(f"cannot stop pid {pid}: {exc}", file=sys.stderr)
            return 1
    for _ in range(20):
        if not _pid_alive(pid):
            break
        time.sleep(0.25)
    _pid_path().unlink(missing_ok=True)
    print(f"stopped pid {pid}")
    return 0


def cmd_status(args) -> int:
    payload = read_status()
    pid = running_pid()
    if not pid:
        print("Nadejda is not running")
        return 1
    print(f"Nadejda is running (pid {pid})")
    if not payload:
        print("  no status file yet")
        return 0
    print(f"  uptime   : {payload.get('uptime')} s")
    print(f"  strategy : {payload.get('strategy')}")
    print(f"  UDP      : {payload.get('udp_strategy')} (QUIC: {payload.get('quic')})")
    print(f"  filter   : {payload.get('filter')}")
    stats = payload.get("stats", {})
    for key in (
        "seen",
        "desynced",
        "data_desynced",
        "udp_desynced",
        "voice_desynced",
        "reassembled",
        "injected",
        "passed",
        "dropped",
        "partial_aborts",
        "errors",
    ):
        print(f"  {key:<15}: {stats.get(key, 0)}")
    return 0


def cmd_test(args) -> int:
    cfg = load_config(args.config)
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        if ok:
            print(f"ok   {name}")
        else:
            failures += 1
            print(f"FAIL {name}" + (f" — {detail}" if detail else ""))

    version = pydivert_version()
    check("pydivert installed", version is not None, version or "pip install pydivert")
    check(
        "administrator rights",
        is_admin(),
        "run from an elevated terminal to actually capture packets",
    )

    win_filter = build_filter(cfg)
    ok, detail = check_filter(win_filter)
    check("WinDivert filter is valid", ok, detail)
    print(f"     filter: {win_filter}")

    engine = WinEngine(cfg)
    # Pick a listed domain that is not covered by an override, so this check
    # exercises the global strategy rather than a per-domain one.
    overridden = HostList(list(cfg.overrides))
    domain = next(
        (name for name in cfg.domains if not overridden.matches(name)),
        cfg.domains[0],
    )
    hello = make_client_hello(domain)
    decision = engine.process(tcp_packet(hello, 443, 1000))
    check(
        f"TCP strategy {cfg.strategy.name} rewrites {domain}",
        decision.drop and bool(decision.packets),
        f"drop={decision.drop} packets={len(decision.packets)}",
    )
    if not cfg.strategy.frag:
        check(
            "all ClientHello bytes are preserved",
            _hello_covered(decision.packets, hello, 1000),
            "the injected segments do not cover the original record",
        )

    for domain, preset in cfg.overrides.items():
        probe = f"www.{domain}" if not domain.startswith("*") else domain
        try:
            hello = make_client_hello(probe)
        except Exception as exc:  # pragma: no cover - ssl quirks
            check(f"override {domain} ({preset})", False, str(exc))
            continue
        decision = engine.process(tcp_packet(hello, 443, 5000))
        check(
            f"override {domain} ({preset})",
            decision.drop and bool(decision.packets),
            f"drop={decision.drop} packets={len(decision.packets)}",
        )

    blob = get_payload("quic_google")
    if blob and is_quic_initial(blob):
        decision = engine.process(udp_packet(blob, 443))
        check(
            f"QUIC strategy {cfg.udp.name} fragments an Initial",
            decision.drop and len(decision.packets) >= 2,
            f"drop={decision.drop} packets={len(decision.packets)}",
        )
    else:
        check("QUIC test payload is available", False, "payloads.quic_google missing")

    voice = get_payload("discord_udp")
    if voice:
        decision = engine.process(udp_packet(voice, 50000))
        check(
            "Discord voice datagrams get fakes",
            decision.drop and bool(decision.packets),
            f"drop={decision.drop} packets={len(decision.packets)}",
        )
    else:
        check("Discord voice test payload is available", False, "payloads.discord_udp missing")

    if failures:
        print(f"\n{failures} check(s) failed")
        return 1
    print("\nall checks passed")
    return 0


def cmd_doctor(args) -> int:
    cfg_path = Path(args.config) if args.config else ensure_config()
    print(f"Nadejda {__version__} for Windows")
    print(f"  python      : {sys.version.split()[0]} ({sys.executable})")
    print(f"  platform    : {sys.platform}")
    print(f"  pydivert    : {pydivert_version() or 'not installed'}")
    print(f"  administrator: {is_admin()}")
    print(f"  config      : {cfg_path} ({'found' if cfg_path.is_file() else 'missing'})")
    print(f"  state dir   : {state_dir()}")
    if cfg_path.is_file():
        cfg = configmod.load(cfg_path)
        print(f"  strategy    : {cfg.strategy.name}")
        print(f"  UDP         : {cfg.udp.name} (QUIC: {cfg.general.quic})")
        print(f"  domains     : {len(cfg.domains)} (+{len(cfg.exclude)} excluded)")
        print(f"  overrides   : {len(cfg.overrides)}")
        print(f"  filter      : {build_filter(cfg)}")
        ok, detail = check_filter(build_filter(cfg))
        print(f"  filter check: {'ok' if ok else detail}")
    pid = read_pid()
    print(f"  running     : {'pid ' + str(pid) if pid and _pid_alive(pid) else 'no'}")
    return 0


def cmd_gui(args) -> int:
    from .gui import main as gui_main

    return gui_main(args.config)


def cmd_config(args) -> int:
    cfg_path = Path(args.config) if args.config else ensure_config()
    print(cfg_path)
    return 0


def _setup_logging(level: str) -> None:
    numeric = getattr(logging, str(level).upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    try:
        _log_path().parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            _log_path(), maxBytes=5 * 1024 * 1024, backupCount=2, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError:
        pass
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    root.addHandler(stream)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nadejda-win",
        description="Nadejda for Windows: DPI desynchronisation through WinDivert.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("start", help="start the engine (needs administrator rights)")
    p.add_argument("--config", help="path to config.toml")
    p.add_argument("--strategy", help="override the TCP strategy for this run")
    p.add_argument("--udp-strategy", help="override the UDP strategy for this run")
    p.add_argument("--log-level", default="info")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", help="stop the running engine")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("status", help="show counters from the running engine")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("test", help="self-check the filter and strategies")
    p.add_argument("--config", help="path to config.toml")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("doctor", help="print the environment")
    p.add_argument("--config", help="path to config.toml")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("gui", help="open the graphical interface")
    p.add_argument("--config", help="path to config.toml")
    p.set_defaults(func=cmd_gui)

    p = sub.add_parser("config", help="print the configuration path")
    p.add_argument("--config", help="path to config.toml")
    p.set_defaults(func=cmd_config)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except SystemExit as exc:
        return int(exc.code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
