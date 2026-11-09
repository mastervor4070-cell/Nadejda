"""Command line interface for Nadejda."""

from __future__ import annotations

import argparse
import fcntl
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, config as configmod
from .config import Config
from .desync import PRESETS, UDP_PRESETS, Strategy, describe_udp
from .engine import Engine
from .firewall import TABLE, Firewall, FirewallConfig
from .resolver import Resolver

LOG = logging.getLogger("nadejda")

RUNDIR = Path("/run/nadejda")
PIDFILE = RUNDIR / "nadejda.pid"
AUTOTUNE_LOCK = Path("/run/nadejda-autotune.lock")
_AUTOTUNE_LOCK_FD: int | None = None
LOGFILE = Path("/var/log/nadejda.log")
DEFAULT_TARGETS = [
    "github.com",
    "www.youtube.com",
    "open.spotify.com",
    "soundcloud.com",
    "chatgpt.com",
    "discord.com",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def is_root() -> bool:
    return os.geteuid() == 0


def systemd_unit_exists(name: str = "nadejda") -> bool:
    candidates = (
        Path(f"/etc/systemd/system/{name}.service"),
        Path(f"/run/systemd/system/{name}.service"),
        Path(f"/usr/lib/systemd/system/{name}.service"),
    )
    return any(path.exists() for path in candidates)


def systemd_unit_active(name: str = "nadejda") -> bool:
    """True when systemd (not a manual ``nadejda start``) owns the process."""
    if not shutil.which("systemctl"):
        return False
    unit = name if name.endswith(".service") else f"{name}.service"
    proc = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        capture_output=True,
    )
    return proc.returncode == 0


def setup_logging(level: str, *, foreground: bool, logfile: Path | None = None) -> None:
    if os.environ.get("NADEJDA_VERBOSE"):
        level = "debug"
    handlers: list[logging.Handler] = []
    if foreground or not logfile:
        handlers.append(logging.StreamHandler(sys.stderr))
    if logfile:
        try:
            logfile.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(logfile, encoding="utf-8"))
        except OSError:
            handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        handlers=handlers,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        force=True,
    )


def read_pid() -> int | None:
    try:
        pid = int(PIDFILE.read_text().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        return pid
    except OSError:
        return None
    return pid


def write_pid() -> None:
    RUNDIR.mkdir(parents=True, exist_ok=True)
    PIDFILE.write_text(f"{os.getpid()}\n")


def clear_pid() -> None:
    try:
        PIDFILE.unlink()
    except OSError:
        pass


def load(args) -> Config:
    return configmod.load(args.config)


def daemonize() -> None:
    if os.fork() > 0:
        # Original process: wait until the daemon has written its pid file so
        # that an immediately following 'nadejda status' sees it.
        deadline = time.time() + 3.0
        while time.time() < deadline and not PIDFILE.exists():
            time.sleep(0.02)
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.chdir("/")
    os.umask(0o022)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    log = os.open(LOGFILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log, 1)
    os.dup2(log, 2)


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------


def probe(
    host: str,
    ip: str,
    timeout: float = 6.0,
    *,
    payload_bytes: int = 32 * 1024,
    payload_timeout: float = 3.0,
) -> tuple[bool, str, float, int]:
    """TLS-probe ``host`` at ``ip`` and read a little of the HTTP response.

    Returns ``(ok, detail, elapsed, received_bytes)``.  Reading the body matters
    for throttling: some ISPs complete the TLS handshake and then limit the
    flow to a few KB/s, which a handshake-only check cannot see.
    """
    started = time.time()
    sock = None
    tls = None
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Nadejda/{__version__}\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode()
        tls.sendall(request)
        data = tls.recv(256)
        status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace") or "?"
        received = len(data)
        if payload_bytes > received:
            deadline = time.time() + payload_timeout
            while received < payload_bytes:
                left = deadline - time.time()
                if left <= 0:
                    break
                tls.settimeout(min(left, 1.0))
                try:
                    chunk = tls.recv(65536)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                received += len(chunk)
        detail = f"{status}, {received / 1024:.0f} KB"
        return True, detail, time.time() - started, received
    except ssl.SSLCertVerificationError:
        return True, "TLS ok (cert mismatch)", time.time() - started, 0
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}", time.time() - started, 0
    finally:
        for obj in (tls, sock):
            if obj:
                try:
                    obj.close()
                except OSError:
                    pass


def test_hosts(cfg: Config, hosts: list[str], timeout: float = 6.0) -> list[tuple[str, bool, str, float]]:
    resolver = Resolver(cfg.general.dns_upstreams, mark=cfg.mark, fallback_udp=False, timeout=timeout)
    results: list[tuple[str, bool, str, float]] = []
    try:
        for host in hosts:
            try:
                addresses = resolver.resolve(host)
            except Exception as exc:  # noqa: BLE001
                results.append((host, False, f"DNS: {exc}", 0.0))
                continue
            if not addresses:
                results.append((host, False, "DNS: no A records", 0.0))
                continue
            last: tuple[bool, str, float] = (False, "no address reachable", 0.0)
            for ip in addresses[:3]:
                ok, detail, elapsed, _received = probe(host, ip, timeout)
                last = (ok, f"{detail} [{ip}]", elapsed)
                if ok:
                    break
            results.append((host, *last))
    finally:
        resolver.close()
    return results


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_start(args) -> int:
    cfg = load(args)
    if not is_root():
        print("nadejda: root privileges are required (nftables + raw sockets)", file=sys.stderr)
        return 1
    if not shutil.which("nft"):
        print("nadejda: nftables is not installed (package 'nftables')", file=sys.stderr)
        return 1
    pid = read_pid()
    if pid:
        print(f"nadejda is already running (pid {pid})")
        return 0
    clear_pid()
    if cfg.general.dns:
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe_sock.bind(("127.0.0.1", cfg.general.dns_port))
        except OSError as exc:
            print(
                f"nadejda: DNS port {cfg.general.dns_port} is already in use: {exc}",
                file=sys.stderr,
            )
            return 1
        finally:
            probe_sock.close()

    engine = Engine(cfg)
    setup_logging(cfg.general.log_level, foreground=args.foreground, logfile=LOGFILE)
    if not args.foreground:
        print("starting nadejda in the background...")
        daemonize()
        write_pid()
    else:
        write_pid()

    def stop_handler(signum, _frame):
        LOG.info("received signal %d, stopping", signum)
        engine.stop_event.set()
        # The queue may not be open yet if the signal arrives during setup.
        try:
            engine.queue.wake()
        except Exception:  # noqa: BLE001
            pass

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    try:
        engine.run()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("fatal error: %s", exc)
        return 1
    finally:
        clear_pid()
    return 0


def cmd_stop(_args) -> int:
    if not is_root():
        print("nadejda: root privileges are required to stop the engine", file=sys.stderr)
        return 1
    pid = read_pid()
    if not pid:
        print("nadejda is not running")
        _cleanup_table()
        return 0
    print(f"stopping nadejda (pid {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.time() + 10
    while time.time() < deadline:
        if not read_pid():
            break
        time.sleep(0.2)
    if read_pid():
        print("process did not exit, killing")
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    clear_pid()
    _cleanup_table()
    print("stopped")
    return 0


def _cleanup_table() -> None:
    if not shutil.which("nft"):
        return
    if not is_root():
        print("note: run with sudo to remove the nftables rules", file=sys.stderr)
        return
    subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True)


def cmd_restart(args) -> int:
    if not is_root():
        print("nadejda: root privileges are required", file=sys.stderr)
        return 1
    cmd_stop(args)
    time.sleep(0.5)
    return cmd_start(args)


def cmd_status(args) -> int:
    cfg = load(args)
    pid = read_pid()
    print(f"Nadejda {__version__}")
    print(f"  config:    {cfg.path}")
    print(f"  state:     {'running (pid ' + str(pid) + ')' if pid else 'stopped'}")
    if shutil.which("nft"):
        if is_root():
            present = subprocess.run(
                ["nft", "list", "table", "inet", TABLE], capture_output=True
            ).returncode == 0
            print(f"  nftables:  {'table inet ' + TABLE + ' present' if present else 'not installed'}")
        else:
            print("  nftables:  unknown (run as root to inspect)")
    print(f"  strategy:  {cfg.strategy.name} ({cfg.strategy.positions}, seqovl={cfg.strategy.seqovl})")
    print(f"  udp/quic:  {cfg.udp.name} — {describe_udp(cfg.udp)}, mode={cfg.general.quic}")
    print(f"  tcp ports: {', '.join(str(p) for p in cfg.general.tcp_ports)}")
    print(f"  udp voice: {', '.join(cfg.general.udp_voice_ports)}")
    print(
        f"  cutoffs:   tcp={cfg.general.tcp_cutoff} udp={cfg.general.udp_cutoff}, "
        f"game={cfg.general.game_filter}"
    )
    if cfg.overrides:
        shown = ", ".join(f"{domain}={preset}" for domain, preset in cfg.overrides.items())
        print(f"  overrides: {shown}")
    print(f"  scope:     {cfg.general.scope}, sni_filter={cfg.general.sni_filter}")
    print(f"  queue:     {cfg.general.queue_num}")
    print(f"  dns proxy: {'on, port ' + str(cfg.general.dns_port) if cfg.general.dns else 'off'}")
    print(f"  log:       {LOGFILE}")
    return 0


def cmd_test(args) -> int:
    cfg = load(args)
    hosts = args.hosts or DEFAULT_TARGETS
    results = test_hosts(cfg, hosts, timeout=args.timeout)
    width = max(len(h) for h in hosts) + 2
    ok_count = 0
    for host, ok, detail, elapsed in results:
        mark = "OK  " if ok else "FAIL"
        if ok:
            ok_count += 1
        print(f"  {host:<{width}} {mark} {detail} ({elapsed:.2f}s)")
    print(f"\n{ok_count}/{len(results)} hosts reachable")
    if any("403" in detail for _h, ok, detail, _e in results if ok):
        print("note: HTTP 403 after a successful TLS handshake is a server-side geo-block, not a DPI issue.")
    # Only full HTML pages can tell us about throttling.  API endpoints and
    # redirects legitimately answer with a tiny body.
    page_hosts = {
        "soundcloud.com",
        "discord.com",
        "www.youtube.com",
        "youtube.com",
        "github.com",
    }
    throttled = []
    for host, ok, detail, _elapsed in results:
        match = re.search(r", (\d+) KB", detail)
        if ok and match and int(match.group(1)) < 16 and host in page_hosts:
            throttled.append(host)
    if throttled:
        print(
            "note: "
            + ", ".join(throttled)
            + " returned less than 16 KB after a successful TLS handshake."
        )
        print("      This looks like SNI throttling; try: sudo nadejda autotune --quick --save")
    return 0 if ok_count == len(results) else 1


# A real page is tens of KB.  A throttled flow typically stalls after 5-20 KB,
# so this threshold separates "works" from "handshake passed, then throttled".
MIN_PAYLOAD = 24 * 1024


def _autotune_candidates(quick: bool) -> list[tuple[str, Strategy]]:
    """Strategies to try, including TTL/fooling variants of the fake ones.

    The TTL of the decoy must be high enough to reach the provider's DPI but low
    enough to die before the server; this differs per network, so it is tuned.
    """
    if quick:
        names = [
            "zapret_general",
            "zapret_google",
            "zapret_fake",
            "zapret_fake_fakedsplit",
            "seqovl568",
            "seqovl_sni",
            "multisplit",
            "split_sni",
            "disorder",
            "split1_disorder",
            "fake_split",
            "fake_split6",
            "fake_split_ttl9",
            "fake_split_ttl12",
            "fake_split_goodsum",
            "fake_split_goodsum_ttl3",
            "fake_split_goodsum_ttl3_disorder",
            "fake_seqovl_ttl6",
            "frag_split",
        ]
    else:
        names = list(PRESETS)
    return [(name, PRESETS[name].clone()) for name in names]


def _fine_candidates() -> list[tuple[str, Strategy]]:
    """Second-stage sweep around the usual winner.

    On some networks the plain ``fake_split_goodsum_ttl3`` works only for part
    of the flows.  Repeating the decoy, changing the TTL or the split point
    changes how reliably the provider's DPI is fooled.

    All variants keep the base preset name so that the saved config still
    points at a strategy the GUI knows about; the exact parameters are written
    explicitly to the ``[desync]`` section anyway.
    """
    base = PRESETS["fake_split_goodsum_ttl3"]
    variants = {
        # Disorder is the current winner; these variants try to make it
        # reliable for every flow, not just most of them.
        "gs_ttl3": {"disorder": True},
        "gs_ttl3_r2": {"disorder": True, "repeat": 2},
        "gs_ttl3_r3": {"disorder": True, "repeat": 3},
        "gs_ttl3_gap0": {"disorder": True, "gap_ms": 0.0},
        "gs_ttl3_gap50": {"disorder": True, "gap_ms": 50.0},
        "gs_ttl3_gap100": {"disorder": True, "gap_ms": 100.0},
        "gs_ttl2": {"disorder": True, "fake_ttl": 2},
        "gs_ttl4": {"disorder": True, "fake_ttl": 4},
        "gs_ttl5": {"disorder": True, "fake_ttl": 5},
        "gs_badsum": {"disorder": True, "fake_badsum": True},
        "gs_pos1": {"disorder": True, "positions": "1"},
        "gs_sni_end": {"disorder": True, "positions": "sni_end"},
        "gs_seqovl": {
            "disorder": True,
            "positions": "1",
            "seqovl": 568,
            "gap_ms": 0.0,
            "repeat": 2,
        },
        # Controls without disorder, for comparison.
        "gs_nodisorder": {},
        "gs_nodisorder_r2": {"repeat": 2},
        "gs_nodisorder_gap50": {"gap_ms": 50.0},
    }
    return [
        (
            label,
            base.clone(
                name=(
                    "fake_split_goodsum_ttl3_disorder"
                    if overrides.get("disorder")
                    else "fake_split_goodsum_ttl3"
                ),
                **overrides,
            ),
        )
        for label, overrides in variants.items()
    ]


def _acquire_autotune_lock() -> bool:
    """Allow only one autotune at a time.

    Two engines would fight over NFQUEUE 200, and the second one deletes the
    first one's nftables table during setup, silently corrupting the results.
    """
    global _AUTOTUNE_LOCK_FD
    try:
        fd = os.open(AUTOTUNE_LOCK, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        return True  # cannot create the lock file: do not block the run
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    # Keep the descriptor open for the lifetime of the process.
    _AUTOTUNE_LOCK_FD = fd
    return True


def autotune_running() -> bool:
    """True when another process currently holds the autotune lock."""
    try:
        fd = os.open(AUTOTUNE_LOCK, os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        os.close(fd)
    return False


def cmd_autotune(args) -> int:
    cfg = load(args)
    if not is_root():
        print("nadejda: root privileges are required for autotune", file=sys.stderr)
        return 1
    if not _acquire_autotune_lock():
        print(
            "nadejda: another autotune is already running; wait for it to finish",
            file=sys.stderr,
        )
        return 1
    setup_logging(cfg.general.log_level, foreground=True)
    dns_was_enabled = cfg.general.dns
    cfg.general.dns = False  # do not touch DNS while tuning
    targets = args.hosts or ["soundcloud.com", "discord.com", "www.youtube.com"]
    # Make sure custom targets are actually desynced by the SNI filter.
    cfg.domains = sorted(set(cfg.domains) | set(targets))
    if args.only:
        names = [name.strip() for name in args.only.split(",") if name.strip()]
        unknown = [name for name in names if name not in PRESETS]
        if unknown:
            print(
                "unknown strategy: " + ", ".join(unknown),
                file=sys.stderr,
            )
            print("available: " + ", ".join(sorted(PRESETS)), file=sys.stderr)
            return 1
        candidates = [(name, PRESETS[name].clone()) for name in names]
    elif args.fine:
        candidates = _fine_candidates()
    else:
        candidates = _autotune_candidates(args.quick)

    service = bool(getattr(args, "service", False))
    masked = False
    if service and shutil.which("systemctl"):
        subprocess.run(["systemctl", "stop", "nadejda"], capture_output=True)
        # A runtime mask stops systemd restarts and GUI clicks from starting a
        # second engine: its setup deletes our nftables table, silently
        # corrupting every result that follows.
        mask = subprocess.run(
            ["systemctl", "mask", "--runtime", "nadejda.service"], capture_output=True
        )
        masked = mask.returncode == 0
        if masked:
            print("nadejda service is paused for the duration of autotune")
        deadline = time.time() + 10
        while read_pid() and time.time() < deadline:
            time.sleep(0.2)
    if read_pid():
        print("stop the running service first: nadejda stop", file=sys.stderr)
        if masked:
            subprocess.run(
                ["systemctl", "unmask", "--runtime", "nadejda.service"],
                capture_output=True,
            )
        return 1
    engine = Engine(cfg)
    results: list[tuple[int, int, int, float, str]] = []
    payload_timeout = getattr(args, "payload_timeout", 4.0)
    print(f"tuning {len(candidates)} strategies against {', '.join(targets)}\n")
    error: str | None = None
    resolver = None
    try:
        engine.start()
        resolver = Resolver(cfg.general.dns_upstreams, mark=cfg.mark, fallback_udp=False)
        addresses: dict[str, list[str]] = {}
        for host in targets:
            try:
                addresses[host] = resolver.resolve(host)
            except Exception as exc:  # noqa: BLE001
                error = f"cannot resolve {host}: {exc}"
                break
        if error is None:
            # Throttling is applied per flow and is not fully deterministic, so a
            # single successful handshake proves nothing.  Try a few addresses and
            # require the host to download real data more than once.
            attempts = 4 if args.fine else 3
            needed = 3 if args.fine else 2
            for name, strategy in candidates:
                engine.reload_strategy(strategy)
                score = 0
                total = 0.0
                total_bytes = 0
                success_total = 0
                details = []
                for host in targets:
                    addrs = addresses.get(host, [])
                    if not addrs:
                        details.append(f"{host.split('.')[0]}:no-dns")
                        continue
                    successes = 0
                    best_bytes = 0
                    tested = 0
                    for index in range(attempts):
                        # Stop as soon as the host cannot reach the required
                        # number of successes, or already reached it.
                        if successes >= needed:
                            break
                        if successes + (attempts - index) < needed:
                            break
                        ip = addrs[index % len(addrs)]
                        good, _detail, elapsed, received = probe(
                            host,
                            ip,
                            args.timeout,
                            payload_bytes=64 * 1024,
                            payload_timeout=payload_timeout,
                        )
                        tested += 1
                        total += elapsed
                        best_bytes = max(best_bytes, received)
                        if good and received >= MIN_PAYLOAD:
                            successes += 1
                    host_ok = successes >= needed
                    score += int(host_ok)
                    success_total += successes
                    total_bytes += best_bytes
                    details.append(f"{host.split('.')[0]}:{successes}/{tested}")
                results.append((score, success_total, total_bytes, total, name))
                print(
                    f"  {name:<22} hosts={score}/{len(targets)} "
                    f"data={total_bytes / 1024:.0f}KB time={total:.1f}s  {' '.join(details)}"
                )
    except Exception as exc:  # noqa: BLE001
        # Never leave the service stopped because of a bug in a probe.
        LOG.exception("autotune failed")
        error = f"autotune failed: {type(exc).__name__}: {exc}"
    finally:
        if resolver is not None:
            resolver.close()
        engine.shutdown()

    best: str | None = None
    best_score = 0
    if results:
        results.sort(key=lambda item: (-item[0], -item[1], -item[2], item[3]))
        best_score, best_successes, best_bytes, _best_time, best = results[0]
        print(
            f"\nbest strategy: {best} "
            f"({best_score}/{len(targets)} hosts, {best_successes} successful transfers, "
            f"best page {best_bytes / 1024:.0f} KB)"
        )
        if best_score == 0:
            print(
                "no strategy got past the throttle consistently: it may be an IP-level or "
                "server-side restriction.  The best of the tested strategies is saved anyway; "
                "if nothing improves, a VPN/proxy is required."
            )
        elif best_score < len(targets):
            print(
                "warning: this strategy did not unblock every target; sites listed above "
                "with a small KB value are still throttled."
            )
    else:
        print(error or "autotune did not run")

    # Save before starting the service again, otherwise it comes back with the
    # old strategy and the whole run has no visible effect.
    if args.save and best is not None:
        cfg.strategy = next(
            strategy for label, strategy in candidates if label == best
        ).clone()
        cfg.general.dns = dns_was_enabled
        written = configmod.save(cfg)
        print(f"saved to {written}")
    elif best is not None:
        print("re-run with --save to write this strategy to the config")

    if service and shutil.which("systemctl"):
        if masked:
            subprocess.run(
                ["systemctl", "unmask", "--runtime", "nadejda.service"],
                capture_output=True,
            )
        started = subprocess.run(
            ["systemctl", "start", "nadejda"], capture_output=True, text=True
        )
        if started.returncode == 0:
            print("nadejda service started")
        else:
            print(
                "could not start the nadejda service: "
                + (started.stderr.strip() or "systemctl start nadejda failed")
            )
    elif best is not None and not args.save:
        print("start it with: systemctl enable --now nadejda   (or: nadejda start)")
    return 0 if best is not None else 1


def cmd_doctor(args) -> int:
    cfg = load(args)
    problems = 0

    def report(ok: bool, text: str, hint: str = "") -> None:
        nonlocal problems
        print(f"  {'[ok]  ' if ok else '[warn]'} {text}")
        if not ok:
            problems += 1
            if hint:
                print(f"         hint: {hint}")

    print("Nadejda doctor\n")
    report(sys.version_info >= (3, 11), f"python {sys.version.split()[0]} (>=3.11)")
    report(is_root(), "root privileges", "use sudo / systemd for start/autotune")
    report(bool(shutil.which("nft")), "nftables present", "pacman -S nftables")
    report(os.path.exists("/proc/net/netfilter") or os.path.isdir("/proc/net/netfilter"), "netfilter available")
    with open("/proc/modules", encoding="utf-8", errors="replace") as fh:
        modules = fh.read()
    report("nfnetlink_queue" in modules or "nf_tables" in modules, "nfnetlink_queue module loaded", "modprobe nfnetlink_queue")
    if shutil.which("nft"):
        if is_root():
            present = subprocess.run(
                ["nft", "list", "table", "inet", TABLE], capture_output=True
            ).returncode == 0
            report(True, f"existing nft table: {'present' if present else 'none'}")
        else:
            report(True, "existing nft table: unknown (need root)")
    for name in ("nfqws", "winws", "ciadpi", "byedpi"):
        found = subprocess.run(["pgrep", "-x", name], capture_output=True).returncode == 0
        if found:
            report(False, f"competing process '{name}' is running", "stop zapret/byedpi: they fight for NFQUEUE")
        else:
            report(True, f"no competing process '{name}'")
    pid = read_pid()
    report(True, f"nadejda pid: {pid or 'not running'}")
    try:
        Resolver(cfg.general.dns_upstreams[:1], fallback_udp=False, timeout=5).resolve("example.com")
        report(True, "DNS-over-TLS reachable")
    except Exception as exc:  # noqa: BLE001
        report(False, f"DNS-over-TLS failed: {exc}", "port 853 may be blocked")
    if cfg.general.dns:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", cfg.general.dns_port))
            report(True, f"DNS proxy port {cfg.general.dns_port} is free")
        except OSError:
            report(pid is not None, f"DNS proxy port {cfg.general.dns_port} is in use", "another resolver occupies it")
        finally:
            sock.close()
    print(f"\n{problems} warning(s)")
    return 0


def cmd_update_lists(args) -> int:
    cfg = load(args)
    resolver = Resolver(cfg.general.dns_upstreams, mark=cfg.mark, fallback_udp=cfg.general.dns_fallback_udp)
    v4, v6 = resolver.resolve_many(cfg.domains)
    resolver.close()
    print(f"resolved {len(cfg.domains)} domains: {len(v4)} IPv4, {len(v6)} IPv6")
    if is_root() and shutil.which("nft"):
        firewall = Firewall(
            FirewallConfig(
                queue_num=cfg.general.queue_num,
                mark=cfg.mark,
                scope=cfg.general.scope,
                quic=cfg.general.quic,
                block_quic=cfg.general.block_quic,
                dns=cfg.general.dns,
                dns_port=cfg.general.dns_port,
            )
        )
        if firewall.exists():
            firewall.update_sets(v4, v6)
            print("nftables sets updated")
        else:
            print("nadejda is not running, sets were not applied")
    return 0


def _pgrep(name: str) -> bool:
    return subprocess.run(["pgrep", "-x", name], capture_output=True).returncode == 0


def _zapret_units() -> list[str]:
    units: set[str] = set()
    if shutil.which("systemctl"):
        proc = subprocess.run(
            ["systemctl", "list-unit-files", "--no-legend", "--plain"],
            capture_output=True,
            text=True,
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            if not parts or not parts[0].endswith(".service"):
                continue
            name = parts[0].lower()
            if any(key in name for key in ("zapret", "byedpi", "ciadpi", "winws")):
                units.add(parts[0])
    return sorted(units)


def _zapret_nft_tables() -> list[tuple[str, str]]:
    if not shutil.which("nft"):
        return []
    proc = subprocess.run(["nft", "list", "tables"], capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    tables: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "table" and "zapret" in parts[2].lower():
            tables.append((parts[1], parts[2]))
    return tables


def cmd_stop_zapret(args) -> int:
    """Stop and disable the classic zapret/byedpi stack."""
    if not args.dry_run and not is_root():
        print("nadejda: root privileges are required (sudo / pkexec)", file=sys.stderr)
        return 1

    units = _zapret_units()
    processes = [name for name in ("nfqws", "winws", "ciadpi", "byedpi", "tpws") if _pgrep(name)]
    tables = _zapret_nft_tables() if is_root() else []

    if not units and not processes and not tables:
        print("zapret is not running")
        return 0

    if args.dry_run:
        for unit in units:
            print(f"would stop/disable {unit}")
        for name in processes:
            print(f"would stop process {name}")
        for family, name in tables:
            print(f"would delete nft table {family} {name}")
        return 0

    for unit in units:
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
        print(f"stopped {unit}")
        if not args.keep_enabled:
            subprocess.run(["systemctl", "disable", unit], capture_output=True)
            print(f"disabled {unit}")

    for name in processes:
        subprocess.run(["pkill", "-TERM", "-x", name], capture_output=True)
    if processes:
        time.sleep(0.5)
    for name in processes:
        if _pgrep(name):
            subprocess.run(["pkill", "-KILL", "-x", name], capture_output=True)
            print(f"killed process {name}")
        else:
            print(f"stopped process {name}")

    # Leftovers happen when zapret was killed with SIGKILL.
    for family, name in _zapret_nft_tables():
        proc = subprocess.run(["nft", "delete", "table", family, name], capture_output=True, text=True)
        if proc.returncode == 0:
            print(f"deleted nft table {family} {name}")
        else:
            print(f"warning: cannot delete nft table {family} {name}: {proc.stderr.strip()}")

    print("zapret disabled")
    return 0


def cmd_set_config(args) -> int:
    """Update a few config options (used by the GUI)."""
    cfg = load(args)
    updates: dict[str, object] = {}
    udp_updates: dict[str, object] = {}
    if args.scope is not None:
        cfg.general.scope = args.scope
        updates["scope"] = args.scope
    if args.quic is not None:
        cfg.general.quic = args.quic
        updates["quic"] = args.quic
    if args.block_quic is not None:
        # Legacy flag: keep the old key and translate it to the new mode.
        cfg.general.block_quic = args.block_quic
        updates["block_quic"] = args.block_quic
        if args.quic is None:
            cfg.general.quic = "off" if args.block_quic == "off" else "block"
            updates["quic"] = cfg.general.quic
    if args.dns is not None:
        cfg.general.dns = args.dns
        updates["dns"] = args.dns
    if args.sni_filter is not None:
        cfg.general.sni_filter = args.sni_filter
        updates["sni_filter"] = args.sni_filter
    if getattr(args, "game_filter", None) is not None:
        cfg.general.game_filter = args.game_filter
        updates["game_filter"] = args.game_filter
    if getattr(args, "tcp_cutoff", None) is not None:
        cfg.general.tcp_cutoff = args.tcp_cutoff
        updates["tcp_cutoff"] = args.tcp_cutoff
    if getattr(args, "udp_cutoff", None) is not None:
        cfg.general.udp_cutoff = args.udp_cutoff
        updates["udp_cutoff"] = args.udp_cutoff
    if getattr(args, "tcp_ports", None):
        ports = [int(item) for item in args.tcp_ports.split(",") if item.strip()]
        cfg.general.tcp_ports = ports
        updates["tcp_ports"] = ports
    if getattr(args, "udp_voice_ports", None):
        ranges = [item.strip() for item in args.udp_voice_ports.split(",") if item.strip()]
        cfg.general.udp_voice_ports = ranges
        updates["udp_voice_ports"] = ranges
    if args.udp_strategy is not None and args.udp_strategy in UDP_PRESETS:
        cfg.udp = UDP_PRESETS[args.udp_strategy].clone()
    if args.udp_split is not None:
        cfg.udp.split = args.udp_split
        udp_updates["split"] = args.udp_split
    if args.udp_disorder is not None:
        cfg.udp.disorder = args.udp_disorder
        udp_updates["disorder"] = args.udp_disorder
    overrides: dict[str, str] | None = None
    if getattr(args, "clear_overrides", False) or getattr(args, "override", None):
        overrides = {} if getattr(args, "clear_overrides", False) else dict(cfg.overrides)
        for item in getattr(args, "override", None) or []:
            domain, sep, preset = item.partition("=")
            domain = domain.strip().lower().lstrip(".")
            preset = preset.strip()
            if not sep or not domain or not preset:
                print(
                    f"nadejda: --override expects DOMAIN=STRATEGY, got {item!r}",
                    file=sys.stderr,
                )
                return 1
            if preset not in PRESETS:
                print(f"nadejda: unknown strategy {preset!r}", file=sys.stderr)
                return 1
            overrides[domain] = preset
    cfg.general.validate()

    if (
        not updates
        and not udp_updates
        and overrides is None
        and not args.strategy
        and not args.udp_strategy
    ):
        print("nothing to change")
        return 0
    try:
        written = configmod.write_updates(
            cfg,
            updates,
            strategy=args.strategy,
            udp=udp_updates or None,
            udp_strategy=args.udp_strategy,
            overrides=overrides,
        )
    except (OSError, ValueError) as exc:
        print(f"nadejda: cannot update {cfg.path}: {exc}", file=sys.stderr)
        return 1
    print(f"saved {written}")

    if args.restart and read_pid():
        if systemd_unit_active() and shutil.which("systemctl"):
            proc = subprocess.run(["systemctl", "restart", "nadejda"], capture_output=True, text=True)
            if proc.returncode == 0:
                print("nadejda service restarted")
            else:
                print("could not restart the service: " + (proc.stderr.strip() or "unknown error"))
        else:
            # The process was started manually (nadejda start), not by systemd.
            runner = Path(__file__).resolve().parent.parent / "run.py"
            proc = subprocess.run(
                [sys.executable, str(runner), "--config", str(cfg.path), "restart"],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                print("nadejda restarted")
            else:
                print(
                    "could not restart nadejda: "
                    + ((proc.stderr or proc.stdout).strip() or "unknown error")
                )
    return 0


def cmd_gui(args) -> int:
    if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        print("nadejda: no graphical session (WAYLAND_DISPLAY / DISPLAY is not set)", file=sys.stderr)
        return 1
    try:
        from .gui import run_gui
    except Exception as exc:  # noqa: BLE001 - missing GTK is a normal condition
        print(
            "nadejda: cannot load the GUI: "
            f"{exc}\ninstall GTK4 bindings: pacman -S python-gobject gtk4 libadwaita",
            file=sys.stderr,
        )
        return 1
    return run_gui(args.config)


def cmd_logs(args) -> int:
    if not LOGFILE.exists():
        print(f"{LOGFILE} does not exist")
        return 1
    lines = LOGFILE.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-args.lines :]:
        print(line)
    return 0


def cmd_config(args) -> int:
    cfg = load(args)
    if args.write_default:
        cfg.path.parent.mkdir(parents=True, exist_ok=True)
        target = cfg.path
        if target.exists():
            # Do not clobber a hand-edited file (comments, custom domains).
            target = target.with_name(target.name + ".new")
        target.write_text(configmod.dump(cfg), encoding="utf-8")
        print(f"wrote {target}")
        return 0
    print(cfg.path)
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nadejda",
        description="Nadejda - transparent DPI desync for Linux (nftables + NFQUEUE)",
    )
    parser.add_argument("--version", action="version", version=f"Nadejda {__version__}")
    parser.add_argument("--config", help="path to config.toml", default=None)
    parser.add_argument("-v", "--verbose", action="count", default=0)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("start", help="start the engine")
    p.add_argument("-f", "--foreground", action="store_true", help="do not daemonize")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", help="stop the engine")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("restart", help="restart the engine")
    p.add_argument("-f", "--foreground", action="store_true")
    p.set_defaults(func=cmd_restart)

    p = sub.add_parser("status", help="show engine status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("test", help="check real connectivity to the target sites")
    p.add_argument("hosts", nargs="*")
    p.add_argument("--timeout", type=float, default=6.0)
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("autotune", help="find a working desync strategy")
    p.add_argument("hosts", nargs="*")
    p.add_argument("--quick", action="store_true")
    p.add_argument(
        "--fine",
        action="store_true",
        help="second-stage sweep around fake_split_goodsum_ttl3 (TTL/repeat/gap)",
    )
    p.add_argument(
        "--only",
        metavar="NAMES",
        help="test only these presets (comma-separated, see nadejda autotune --quick)",
    )
    p.add_argument("--save", action="store_true")
    p.add_argument("--service", action="store_true", help="stop/start the systemd unit around tuning")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument(
        "--payload-timeout",
        type=float,
        default=4.0,
        help="seconds to wait for a real HTTP body per host (throttle check)",
    )
    p.set_defaults(func=cmd_autotune)

    p = sub.add_parser("gui", help="open the graphical interface (GTK4)")
    p.set_defaults(func=cmd_gui)

    p = sub.add_parser("stop-zapret", help="stop and disable zapret/byedpi")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--keep-enabled", action="store_true", help="stop but keep autostart enabled")
    p.set_defaults(func=cmd_stop_zapret)

    p = sub.add_parser("set-config", help="update config options (used by the GUI)")
    p.add_argument("--strategy", choices=sorted(PRESETS))
    p.add_argument("--udp-strategy", choices=sorted(UDP_PRESETS))
    p.add_argument("--udp-split", type=int)
    p.add_argument("--udp-disorder", action=argparse.BooleanOptionalAction, default=None)
    p.add_argument(
        "--override",
        action="append",
        metavar="DOMAIN=STRATEGY",
        help="use another TCP strategy for a domain and its subdomains (repeatable)",
    )
    p.add_argument(
        "--clear-overrides",
        action="store_true",
        help="remove all per-domain strategy overrides",
    )
    p.add_argument("--scope", choices=("all", "list"))
    p.add_argument("--quic", choices=("desync", "block", "off"))
    p.add_argument("--block-quic", choices=("all", "list", "off"))
    p.add_argument("--dns", action=argparse.BooleanOptionalAction, default=None)
    p.add_argument("--sni-filter", action=argparse.BooleanOptionalAction, default=None)
    p.add_argument("--game-filter", choices=("off", "tcp", "udp", "all"))
    p.add_argument("--tcp-cutoff", type=int)
    p.add_argument("--udp-cutoff", type=int)
    p.add_argument("--tcp-ports", help="comma-separated, e.g. 80,443,8443")
    p.add_argument("--udp-voice-ports", help="comma-separated ranges, e.g. 19294-19344,50000-50100")
    p.add_argument("--restart", action="store_true", help="restart Nadejda after saving")
    p.set_defaults(func=cmd_set_config)

    p = sub.add_parser("doctor", help="diagnose the environment")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("update-lists", help="refresh resolved address sets")
    p.set_defaults(func=cmd_update_lists)

    p = sub.add_parser("logs", help="show the log tail")
    p.add_argument("-n", "--lines", type=int, default=100)
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("config", help="print or create the config")
    p.add_argument("--write-default", action="store_true")
    p.set_defaults(func=cmd_config)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verbose:
        os.environ["NADEJDA_VERBOSE"] = "1"
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        )
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("NADEJDA_VERBOSE"):
            raise
        print(f"nadejda: {exc}", file=sys.stderr)
        return 1
