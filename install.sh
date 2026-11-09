#!/usr/bin/env bash
#
# Nadejda installer / uninstaller.
#
#   sudo ./install.sh                # install, stop zapret, enable at boot
#   sudo ./install.sh --start        # same, and start Nadejda right away
#   sudo ./install.sh --no-systemd   # install files only
#   sudo ./install.sh --keep-zapret  # do not stop/disable zapret
#   sudo ./install.sh --uninstall    # remove everything except /etc/nadejda
#
set -euo pipefail

PREFIX="/opt/nadejda"
BIN="/usr/local/bin/nadejda"
GUI_BIN="/usr/local/bin/nadejda-gui"
CONFDIR="/etc/nadejda"
CONFIG="${CONFDIR}/config.toml"
UNIT="/etc/systemd/system/nadejda.service"
RUNDIR="/run/nadejda"
LOGFILE="/var/log/nadejda.log"
ICON="/usr/share/icons/hicolor/scalable/apps/nadejda.svg"
DESKTOP="/usr/share/applications/io.github.nadejda.Nadejda.desktop"

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

START=0
SYSTEMD=1
UNINSTALL=0
KEEP_ZAPRET=0

usage() {
    sed -n '3,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --start)       START=1 ;;
        --no-systemd)  SYSTEMD=0 ;;
        --uninstall)   UNINSTALL=1 ;;
        --keep-zapret) KEEP_ZAPRET=1 ;;
        -h|--help)     usage; exit 0 ;;
        *)
            echo "unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "nadejda: run this script as root (sudo ./install.sh)" >&2
    exit 1
fi

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# zapret: stop and disable (it competes for the same NFQUEUE)
# ---------------------------------------------------------------------------

zapret_units() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl list-unit-files --no-legend --plain 2>/dev/null \
        | awk '{print $1}' \
        | grep -Ei 'zapret|byedpi|ciadpi|winws' || true
}

stop_zapret() {
    if [[ "$KEEP_ZAPRET" -eq 1 ]]; then
        say "--keep-zapret: leaving zapret/byedpi untouched"
        return 0
    fi
    say "stopping zapret/byedpi (use --keep-zapret to keep it)"

    local unit proc family name
    while IFS= read -r unit; do
        [[ -n "$unit" ]] || continue
        systemctl stop "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
        echo "  stopped and disabled $unit"
    done < <(zapret_units)

    for proc in nfqws winws ciadpi byedpi tpws; do
        if pgrep -x "$proc" >/dev/null 2>&1; then
            pkill -TERM -x "$proc" 2>/dev/null || true
            sleep 0.3
            pkill -KILL -x "$proc" 2>/dev/null || true
            echo "  stopped process $proc"
        fi
    done

    # Leftover tables happen when zapret was killed with SIGKILL.
    if command -v nft >/dev/null 2>&1; then
        while read -r family name; do
            [[ -n "${family:-}" && -n "${name:-}" ]] || continue
            if nft delete table "$family" "$name" 2>/dev/null; then
                echo "  removed leftover nft table $family $name"
            fi
        done < <(nft list tables 2>/dev/null | awk '$1 == "table" && $3 ~ /zapret/ {print $2, $3}')
    fi
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------

if [[ "$UNINSTALL" -eq 1 ]]; then
    say "stopping and disabling Nadejda"
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        systemctl stop nadejda.service 2>/dev/null || true
        systemctl disable nadejda.service 2>/dev/null || true
        rm -f "$UNIT"
        systemctl daemon-reload 2>/dev/null || true
    fi
    if [[ -x "$BIN" ]]; then
        "$BIN" stop 2>/dev/null || true
    fi
    nft delete table inet nadejda 2>/dev/null || true
    rm -f "$BIN" "$GUI_BIN" "$ICON" "$DESKTOP" "$LOGFILE"
    rm -rf "$PREFIX" "$RUNDIR"
    command -v gtk4-update-icon-cache >/dev/null 2>&1 \
        && gtk4-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
    command -v update-desktop-database >/dev/null 2>&1 \
        && update-desktop-database -q /usr/share/applications 2>/dev/null || true
    say "removed. Configuration kept in $CONFDIR (delete it manually if not needed)."
    exit 0
fi

# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

PYTHON="$(command -v python3 || true)"
if [[ -z "$PYTHON" ]]; then
    echo "nadejda: python3 is required" >&2
    exit 1
fi
if ! "$PYTHON" -c 'import sys, tomllib; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "nadejda: Python 3.11+ with tomllib is required (found $("$PYTHON" -V 2>&1))" >&2
    exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
    warn "nftables is not installed: pacman -S nftables   (or: apt install nftables)"
fi
if ! command -v unshare >/dev/null 2>&1; then
    warn "util-linux/unshare not found; 'make test' will not work (the program itself is fine)"
fi
if ! "$PYTHON" -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1"); from gi.repository import Gtk, Adw' >/dev/null 2>&1; then
    warn "GTK4 / libadwaita Python bindings not found; the GUI needs:"
    warn "  pacman -S python-gobject gtk4 libadwaita   (or: apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1)"
fi
if ! command -v pkexec >/dev/null 2>&1; then
    warn "pkexec/polkit not found; the GUI will not be able to start/stop the service"
fi

stop_zapret

# ---------------------------------------------------------------------------
# install files
# ---------------------------------------------------------------------------

say "installing program files to $PREFIX"
rm -rf "${PREFIX}.new"
install -d -m 0755 "${PREFIX}.new"
(cd "$SOURCE_DIR" && cp -a nadejda run.py "$PREFIX.new/")
for extra in README.md Makefile config systemd tests data LICENSE; do
    if [[ -e "$SOURCE_DIR/$extra" ]]; then
        cp -a "$SOURCE_DIR/$extra" "${PREFIX}.new/"
    fi
done
find "${PREFIX}.new" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf "$PREFIX"
mv "${PREFIX}.new" "$PREFIX"

say "installing $BIN"
install -d -m 0755 "$(dirname "$BIN")"
cat > "$BIN" <<EOF
#!/bin/sh
# Generated by the Nadejda installer.
exec "$PYTHON" "$PREFIX/run.py" "\$@"
EOF
chmod 0755 "$BIN"

say "installing $GUI_BIN and the desktop entry"
cat > "$GUI_BIN" <<EOF
#!/bin/sh
# Generated by the Nadejda installer.
exec "$PYTHON" "$PREFIX/run.py" gui "\$@"
EOF
chmod 0755 "$GUI_BIN"

install -D -m 0644 "$SOURCE_DIR/data/nadejda.svg" "$ICON"
install -D -m 0644 "$SOURCE_DIR/data/io.github.nadejda.Nadejda.desktop" "$DESKTOP"
command -v gtk4-update-icon-cache >/dev/null 2>&1 \
    && gtk4-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database -q /usr/share/applications 2>/dev/null || true

say "installing configuration"
install -d -m 0755 "$CONFDIR"
if [[ -f "$CONFIG" ]]; then
    install -m 0644 "$SOURCE_DIR/config/config.toml" "${CONFIG}.new"
    say "kept existing $CONFIG (defaults written to ${CONFIG}.new)"
else
    install -m 0644 "$SOURCE_DIR/config/config.toml" "$CONFIG"
fi

if [[ "$SYSTEMD" -eq 1 ]]; then
    if [[ -d /run/systemd/system ]]; then
        say "installing systemd unit"
        install -m 0644 "$SOURCE_DIR/systemd/nadejda.service" "$UNIT"
        systemctl daemon-reload
        systemctl enable nadejda.service >/dev/null
        if [[ "$START" -eq 1 ]]; then
            say "starting nadejda"
            systemctl restart nadejda.service
        else
            say "unit enabled at boot (not started yet)"
        fi
    else
        warn "systemd is not running; skipped unit installation"
    fi
fi

cat <<'EOF'

Nadejda is installed.

Next steps:
  1. sudo nadejda doctor              # check the environment
  2. sudo nadejda autotune --quick --save
                                      # find a working strategy for your ISP
  3. sudo systemctl start nadejda     # or: sudo nadejda start
  4. nadejda test                     # check the target sites
  5. nadejda-gui                      # or launch "Nadejda" from the app menu
  6. nadejda status / nadejda logs    # diagnostics

zapret/byedpi was stopped unless you passed --keep-zapret.
EOF
