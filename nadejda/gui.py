"""GTK4 / libadwaita front-end for Nadejda.

The GUI runs as a normal user.  Actions that need root (start/stop, autotune,
saving /etc/nadejda/config.toml) are executed through ``pkexec`` when a polkit
agent is available, and through ``sudo -A`` with a zenity/kdialog password
prompt otherwise (the KDE agent refuses to run outside Plasma, for example on
Hyprland).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Pango", "1.0")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango  # noqa: E402

from . import __version__, config as configmod  # noqa: E402
from .cli import (  # noqa: E402
    DEFAULT_TARGETS,
    autotune_running,
    read_pid,
    systemd_unit_active,
    systemd_unit_exists,
    test_hosts,
)
from .desync import PRESETS, UDP_PRESETS, describe, describe_udp  # noqa: E402

APP_ID = "io.github.nadejda.Nadejda"
LOGFILE = Path("/var/log/nadejda.log")
DEFAULT_CONFIG = Path("/etc/nadejda/config.toml")
UNIT = "nadejda.service"

CSS = """
.status-card { padding: 22px; border-radius: 18px; }
.status-title { font-size: 25px; font-weight: 800; }
.status-sub { font-size: 13px; }
.status-on { color: #2ec27e; }
.status-off { color: #9a9996; }
.host-ok { color: #2ec27e; }
.host-fail { color: #e01b24; }
.host-wait { color: #9a9996; }
.task-label { font-size: 12px; }
.log-view { font-size: 12px; }
.status-chip {
    padding: 3px 10px;
    border-radius: 999px;
    background: alpha(currentColor, 0.10);
}
.status-chip-dot { font-size: 10px; }
.status-chip-label { font-size: 12px; font-weight: 700; }
.status-chip-strategy { font-size: 12px; opacity: 0.72; }
"""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _cli_argv() -> list[str]:
    runner = _project_root() / "run.py"
    if runner.is_file():
        return [sys.executable, str(runner)]
    installed = shutil.which("nadejda")
    if installed:
        return [installed]
    raise RuntimeError("cannot find the nadejda executable")


def _resolve_config(path: str | Path | None) -> Path:
    raw = path or os.environ.get("NADEJDA_CONFIG") or DEFAULT_CONFIG
    return Path(raw).expanduser().resolve()


def _which_pkexec() -> str | None:
    found = shutil.which("pkexec")
    if found:
        return found
    candidate = Path("/usr/bin/pkexec")
    return str(candidate) if candidate.exists() else None


POLKIT_AGENT_MARKERS = (
    "polkit-kde-authentication",
    "polkit-gnome-authentication",
    "hyprpolkitagent",
    "lxpolkit",
    "mate-polkit",
    "polkit-1-authentication",
)


def _polkit_agent_running() -> bool:
    try:
        proc = subprocess.run(
            ["pgrep", "-af", "polkit"], capture_output=True, text=True
        )
    except OSError:
        return False
    for line in proc.stdout.splitlines():
        _, _, command = line.partition(" ")
        command = command.strip().lower()
        if not command or "pgrep" in command:
            continue
        if any(marker in command for marker in POLKIT_AGENT_MARKERS):
            return True
    return False


def _askpass_script() -> Path | None:
    """A tiny SUDO_ASKPASS helper that shows a graphical password prompt."""
    if shutil.which("zenity"):
        command = 'exec zenity --password --title="Nadejda: права администратора"'
    elif shutil.which("kdialog"):
        command = 'exec kdialog --password "Nadejda: права администратора"'
    else:
        return None

    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    target = cache / "nadejda" / "askpass.sh"
    content = "#!/bin/sh\n" + command + "\n"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.is_file() or target.read_text(encoding="utf-8") != content:
            target.write_text(content, encoding="utf-8")
            target.chmod(0o700)
    except OSError:
        return None
    return target


class NadejdaWindow(Adw.ApplicationWindow):
    def __init__(self, app: "NadejdaApp", config_path: Path):
        super().__init__(
            application=app,
            title="Nadejda",
            default_width=980,
            default_height=780,
        )
        # Keep the layout readable when the compositor tiles the window narrow.
        self.set_size_request(460, 480)
        self.app = app
        self.config_path = config_path
        self.cfg = configmod.load(config_path)
        self._running = read_pid() is not None
        self._busy = False
        self._updating = False
        self._loading_settings = False
        self._polkit_agent = False
        self._askpass_env: dict[str, str] | None = None
        self._rows: dict[str, tuple[Adw.ActionRow, Gtk.Image]] = {}
        self._test_ok = 0
        self._last_task_lines: list[str] = []
        self._log_view: Gtk.TextView | None = None
        self._log_buffer: Gtk.TextBuffer | None = None

        self._build_ui()
        self._load_settings()
        self._refresh_status(force=True)
        self._refresh_logs()

        GLib.timeout_add_seconds(2, self._poll_status)
        GLib.timeout_add_seconds(3, self._auto_logs_tick)
        GLib.timeout_add(700, self._ensure_polkit_agent)

    # -- construction -------------------------------------------------------

    def _build_ui(self) -> None:
        self.stack = Adw.ViewStack()
        self.stack.connect("notify::visible-child-name", self._on_page_changed)

        header = Adw.HeaderBar()
        switcher = Adw.ViewSwitcherTitle()
        switcher.set_stack(self.stack)
        switcher.set_title("Nadejda")
        switcher.set_subtitle("обход DPI")
        header.set_title_widget(switcher)

        menu = Gio.Menu()
        menu.append("О программе", "app.about")
        menu.append("Выход", "app.quit")
        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic")
        menu_button.set_menu_model(menu)

        # Live status pill: visible on every page, so the user does not need to
        # return to "Главная" just to see whether the engine is running.
        self.header_chip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.header_chip.add_css_class("status-chip")
        self.header_chip.set_valign(Gtk.Align.CENTER)
        self.header_dot = Gtk.Label(label="●")
        self.header_dot.add_css_class("status-chip-dot")
        self.header_dot.add_css_class("status-off")
        self.header_state = Gtk.Label(label="Выключено")
        self.header_state.add_css_class("status-chip-label")
        self.header_sep = Gtk.Label(label="·")
        self.header_sep.add_css_class("status-chip-strategy")
        self.header_strategy = Gtk.Label(label="")
        self.header_strategy.add_css_class("status-chip-strategy")
        self.header_strategy.set_ellipsize(Pango.EllipsizeMode.END)
        self.header_strategy.set_max_width_chars(30)
        for widget in (
            self.header_dot,
            self.header_state,
            self.header_sep,
            self.header_strategy,
        ):
            self.header_chip.append(widget)

        header_right = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        header_right.set_valign(Gtk.Align.CENTER)
        header_right.append(self.header_chip)
        header_right.append(menu_button)
        header.pack_end(header_right)

        self.toast_overlay = Adw.ToastOverlay()

        self.stack.add_titled(self._build_home(), "home", "Главная")
        self.stack.add_titled(self._build_settings(), "settings", "Настройки")
        self.stack.add_titled(self._build_logs(), "logs", "Журнал")

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(self.stack)
        self.toast_overlay.set_child(toolbar)
        self.set_content(self.toast_overlay)

    def _build_home(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.set_margin_top(22)
        page.set_margin_bottom(24)
        page.set_margin_start(20)
        page.set_margin_end(20)

        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        card.add_css_class("card")
        card.add_css_class("status-card")

        self.status_icon = Gtk.Image.new_from_icon_name("security-low-symbolic")
        self.status_icon.set_pixel_size(56)
        self.status_icon.set_valign(Gtk.Align.CENTER)
        self.status_icon.add_css_class("status-off")

        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        titles.set_hexpand(True)
        titles.set_valign(Gtk.Align.CENTER)
        self.status_title = Gtk.Label(label="Nadejda выключена", xalign=0)
        self.status_title.add_css_class("status-title")
        self.status_sub = Gtk.Label(label="", xalign=0)
        self.status_sub.add_css_class("status-sub")
        self.status_sub.add_css_class("dim-label")
        self.status_sub.set_wrap(True)
        titles.append(self.status_title)
        titles.append(self.status_sub)

        self.status_switch = Gtk.Switch()
        self.status_switch.set_valign(Gtk.Align.CENTER)
        self.status_switch.connect("notify::active", self._on_switch)

        card.append(self.status_icon)
        card.append(titles)
        card.append(self.status_switch)
        page.append(card)

        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row1.set_homogeneous(True)
        self.btn_test = self._action_button(
            "Проверить сайты", "network-transmit-receive-symbolic", self._on_test
        )
        self.btn_autotune = self._action_button(
            "Автоподбор", "emblem-system-symbolic", self._on_autotune
        )
        row1.append(self.btn_test)
        row1.append(self.btn_autotune)

        row2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row2.set_homogeneous(True)
        self.btn_logs = self._action_button(
            "Журнал", "text-x-generic-symbolic", self._on_open_logs
        )
        row2.append(self.btn_logs)

        page.append(row1)
        page.append(row2)

        task = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.spinner = Gtk.Spinner()
        self.spinner.set_visible(False)
        self.task_label = Gtk.Label(label="", xalign=0)
        self.task_label.add_css_class("task-label")
        self.task_label.add_css_class("dim-label")
        self.task_label.set_ellipsize(Pango.EllipsizeMode.END)
        self.task_label.set_hexpand(True)
        self.task_label.set_visible(False)
        task.append(self.spinner)
        task.append(self.task_label)
        page.append(task)

        self.results_group = Adw.PreferencesGroup(title="Проверка сайтов")
        self.results_group.set_visible(False)
        page.append(self.results_group)

        hint = Gtk.Label(
            label="Nadejda работает как служба. Действия требуют подтверждения администратора.",
            xalign=0,
        )
        hint.add_css_class("dim-label")
        hint.set_wrap(True)
        page.append(hint)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(900)
        clamp.set_tightening_threshold(640)
        clamp.set_child(page)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_child(clamp)
        scrolled.set_vexpand(True)
        return scrolled

    def _action_button(self, label: str, icon: str, callback) -> Gtk.Button:
        # Gtk.Button shows either a label or an icon, so build the content by hand
        # to get "icon + text" pills.
        button = Gtk.Button()
        content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        content.set_halign(Gtk.Align.CENTER)
        image = Gtk.Image.new_from_icon_name(icon)
        image.set_pixel_size(16)
        text = Gtk.Label(label=label)
        content.append(image)
        content.append(text)
        button.set_child(content)
        button.add_css_class("pill")
        button.set_hexpand(True)
        button.connect("clicked", callback)
        return button

    def _build_settings(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()

        group = Adw.PreferencesGroup(
            title="Обход DPI",
            description="Изменения сохраняются в файл конфигурации и применяются после перезапуска.",
        )

        self._strategy_names = list(PRESETS)
        self.strategy_row = Adw.ComboRow(title="Стратегия")
        self.strategy_row.set_model(Gtk.StringList.new(self._strategy_names))
        self.strategy_row.set_subtitle("")
        self.strategy_row.connect("notify::selected", self._on_strategy_changed)
        group.add(self.strategy_row)

        self._scope_values = ["all", "list"]
        self.scope_row = Adw.ComboRow(title="Область обработки")
        self.scope_row.set_model(
            Gtk.StringList.new(["Все адреса (рекомендуется)", "Только домены из списка"])
        )
        group.add(self.scope_row)

        self._quic_values = ["desync", "block", "off"]
        self.quic_row = Adw.ComboRow(title="QUIC (UDP/443)")
        self.quic_row.set_model(
            Gtk.StringList.new(
                ["Обходить (фрагментация)", "Блокировать", "Не трогать"]
            )
        )
        self.quic_row.set_subtitle("TCP-обход работает всегда; QUIC обходится фрагментацией")
        group.add(self.quic_row)

        self._udp_names = list(UDP_PRESETS)
        self.udp_row = Adw.ComboRow(title="Стратегия UDP/QUIC")
        self.udp_row.set_model(Gtk.StringList.new(self._udp_names))
        self.udp_row.set_subtitle("")
        self.udp_row.connect("notify::selected", self._on_udp_changed)
        group.add(self.udp_row)

        self.sni_row = Adw.SwitchRow(title="Фильтр по SNI")
        self.sni_row.set_subtitle("Обрабатывать только ClientHello из списка доменов")
        group.add(self.sni_row)

        page.add(group)

        dns_group = Adw.PreferencesGroup(title="DNS")
        self.dns_row = Adw.SwitchRow(title="DNS-over-TLS прокси")
        self.dns_row.set_subtitle("Перехватывать порт 53 и не доверять DNS провайдера")
        dns_group.add(self.dns_row)
        page.add(dns_group)

        apply_group = Adw.PreferencesGroup()
        apply_row = Adw.ActionRow(title="Применить настройки")
        apply_row.set_subtitle(str(self.config_path))
        apply_row.set_activatable(False)
        self.btn_save = Gtk.Button(label="Сохранить")
        self.btn_save.add_css_class("suggested-action")
        self.btn_save.connect("clicked", self._on_save_settings)
        apply_row.add_suffix(self.btn_save)
        reset = Gtk.Button(label="Сбросить")
        reset.connect("clicked", lambda *_: self._load_settings())
        apply_row.add_suffix(reset)
        apply_group.add(apply_row)
        page.add(apply_group)

        return page

    def _build_logs(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.set_margin_top(18)
        page.set_margin_bottom(18)
        page.set_margin_start(18)
        page.set_margin_end(18)

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        title = Gtk.Label(label="Журнал Nadejda", xalign=0)
        title.add_css_class("title-3")
        title.set_hexpand(True)
        self.auto_logs = Gtk.Switch()
        self.auto_logs.set_valign(Gtk.Align.CENTER)
        self.auto_logs.set_active(True)
        auto_label = Gtk.Label(label="Автообновление")
        auto_label.add_css_class("dim-label")
        refresh = Gtk.Button(label="Обновить")
        refresh.set_icon_name("view-refresh-symbolic")
        refresh.connect("clicked", lambda *_: self._refresh_logs())
        top.append(title)
        top.append(auto_label)
        top.append(self.auto_logs)
        top.append(refresh)
        page.append(top)

        self._log_buffer = Gtk.TextBuffer()
        self._log_view = Gtk.TextView(buffer=self._log_buffer)
        self._log_view.set_editable(False)
        self._log_view.set_cursor_visible(False)
        self._log_view.set_monospace(True)
        self._log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self._log_view.set_top_margin(10)
        self._log_view.set_bottom_margin(10)
        self._log_view.set_left_margin(10)
        self._log_view.set_right_margin(10)
        self._log_view.add_css_class("log-view")

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.add_css_class("card")
        scrolled.set_child(self._log_view)
        page.append(scrolled)
        return page

    # -- services / privileges ----------------------------------------------

    def _admin_prefix(self) -> list[str]:
        """Privilege escalation: pkexec with a live agent, else sudo + askpass."""
        if os.geteuid() == 0:
            return []
        if self._polkit_agent:
            pkexec = _which_pkexec()
            if pkexec:
                return [pkexec]
        askpass = _askpass_script()
        if askpass and shutil.which("sudo"):
            self._askpass_env = os.environ.copy()
            self._askpass_env["SUDO_ASKPASS"] = str(askpass)
            self._askpass_env["SUDO_ASKPASS_REQUIRE"] = "force"
            return ["sudo", "-A"]
        pkexec = _which_pkexec()
        if pkexec:
            return [pkexec]
        raise RuntimeError(
            "Не найдено средство повышения прав.\n\n"
            "Установите polkit-агент (hyprpolkitagent, polkit-gnome) "
            "или запустите действие из терминала через sudo."
        )

    def _admin_cli(self, args: list[str]) -> list[str]:
        base = _cli_argv() + ["--config", str(self.config_path)] + args
        return self._admin_prefix() + base

    def _admin_systemctl(self, *args: str) -> list[str]:
        return self._admin_prefix() + ["systemctl", *args]

    def _ensure_polkit_agent(self) -> bool:
        if os.geteuid() == 0 or not _which_pkexec():
            return False
        if _polkit_agent_running():
            self._polkit_agent = True
            return False
        candidates = (
            "/usr/lib/polkit-kde-authentication-agent-1",
            "/usr/lib/polkit-gnome-authentication-agent-1",
            "/usr/libexec/polkit-gnome-authentication-agent-1",
            "/usr/bin/hyprpolkitagent",
            "/usr/bin/lxpolkit",
        )
        for candidate in candidates:
            if not Path(candidate).exists():
                continue
            try:
                proc = subprocess.Popen(
                    [candidate],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError:
                continue
            # The KDE agent silently exits outside Plasma, so check that it stays up.
            for _ in range(8):
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                self._polkit_agent = True
                return False
            try:
                proc.wait(timeout=0)
            except Exception:  # noqa: BLE001 - already dead
                pass
        return False

    # -- status -------------------------------------------------------------

    def _poll_status(self) -> bool:
        try:
            running = read_pid() is not None
        except Exception:  # noqa: BLE001
            running = False
        if running != self._running:
            self._refresh_status(force=True)
        return True

    def _set_switch(self, active: bool) -> None:
        self._updating = True
        try:
            self.status_switch.set_active(active)
        finally:
            self._updating = False

    def _refresh_status(self, *, force: bool = False) -> None:
        try:
            pid = read_pid()
        except Exception:  # noqa: BLE001
            pid = None
        running = pid is not None
        changed = force or running != self._running
        self._running = running
        if changed:
            self._set_switch(running)

        self.status_title.set_text("Nadejda работает" if running else "Nadejda выключена")
        self.status_icon.set_from_icon_name(
            "security-high-symbolic" if running else "security-low-symbolic"
        )
        for css in ("status-on", "status-off"):
            self.status_icon.remove_css_class(css)
        self.status_icon.add_css_class("status-on" if running else "status-off")

        parts = [
            f"Стратегия: {self.cfg.strategy.name}",
            f"очередь {self.cfg.general.queue_num}",
        ]
        if self.cfg.general.dns:
            parts.append(f"DNS :{self.cfg.general.dns_port}")
        if running and pid:
            parts.append(f"pid {pid}")
        self.status_sub.set_text(" · ".join(parts))

        # Keep the header pill in sync with the same state.
        self.header_state.set_text("Работает" if running else "Выключено")
        self.header_strategy.set_text(self.cfg.strategy.name)
        self.header_sep.set_visible(bool(self.cfg.strategy.name))
        self.header_chip.set_tooltip_text(
            ("Nadejda работает" if running else "Nadejda выключена")
            + f"\nСтратегия: {self.cfg.strategy.name}"
            + (f"\nPID: {pid}" if running and pid else "")
        )
        for css in ("status-on", "status-off"):
            self.header_dot.remove_css_class(css)
        self.header_dot.add_css_class("status-on" if running else "status-off")

    # -- tasks --------------------------------------------------------------

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        self.spinner.set_visible(busy)
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()
        self.task_label.set_visible(busy)
        if text:
            self.task_label.set_text(text)
        for widget in (
            self.btn_test,
            self.btn_autotune,
            self.btn_save,
            self.status_switch,
        ):
            widget.set_sensitive(not busy)

    def _toast(self, text: str) -> None:
        toast = Adw.Toast.new(text)
        toast.set_timeout(4)
        self.toast_overlay.add_toast(toast)

    def _friendly_error(self, text: str) -> str:
        low = (text or "").lower()
        if any(
            marker in low
            for marker in (
                "authentication agent",
                "not authorized",
                "not permitted",
                "dismissed",
                "no password was provided",
                "incorrect password",
                "a password is required",
                "a terminal is required",
            )
        ):
            return (
                "Не удалось получить права администратора.\n\n"
                "Введите пароль в графическом окне или запустите действие из "
                "терминала через sudo. Для pkexec нужен polkit-агент "
                "(hyprpolkitagent / polkit-gnome).\n\n"
                f"Ответ системы:\n{text[-900:]}"
            )
        return (text or "Неизвестная ошибка")[-1600:]

    def _show_error(self, heading: str, body: str) -> None:
        dialog = Adw.AlertDialog(heading=heading, body=self._friendly_error(body))
        dialog.add_response("close", "Закрыть")
        dialog.set_default_response("close")
        dialog.set_close_response("close")
        dialog.connect("response", lambda d, _r: d.close())
        dialog.present(self)

    def _confirm(
        self,
        heading: str,
        body: str,
        label: str,
        callback,
        *,
        destructive: bool = False,
    ) -> None:
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("ok", label)
        dialog.set_response_appearance(
            "ok",
            Adw.ResponseAppearance.DESTRUCTIVE
            if destructive
            else Adw.ResponseAppearance.SUGGESTED,
        )
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def on_response(d, response):
            d.close()
            if response == "ok":
                callback()

        dialog.connect("response", on_response)
        dialog.present(self)

    def _run_argv(self, argv: list[str], done) -> None:
        def worker():
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=240,
                    env=self._askpass_env,
                )
                rc = proc.returncode
                output = (proc.stdout + proc.stderr).strip()
            except Exception as exc:  # noqa: BLE001
                rc, output = 1, f"{type(exc).__name__}: {exc}"
            GLib.idle_add(done, rc, output)

        threading.Thread(target=worker, daemon=True).start()

    def _run_stream(self, argv: list[str], on_line, done) -> None:
        def worker():
            lines: list[str] = []
            try:
                proc = subprocess.Popen(
                    argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=self._askpass_env,
                )
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(done, 1, f"{type(exc).__name__}: {exc}")
                return
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                lines.append(line)
                GLib.idle_add(on_line, line)
            rc = proc.wait()
            GLib.idle_add(done, rc, "\n".join(lines[-30:]))

        threading.Thread(target=worker, daemon=True).start()

    # -- start / stop -------------------------------------------------------

    def _on_switch(self, switch: Gtk.Switch, _pspec) -> None:
        if self._updating or self._busy:
            return
        want = switch.get_active()
        if want == self._running:
            return
        if want:
            self._start_engine()
        else:
            self._stop_engine()

    def _start_engine(self) -> None:
        if autotune_running():
            self._set_switch(False)
            self._toast("Идёт автоподбор стратегии — дождитесь его окончания")
            return
        try:
            argv = (
                self._admin_systemctl("start", UNIT)
                if systemd_unit_exists()
                else self._admin_cli(["start"])
            )
        except RuntimeError as exc:
            self._show_error("Запуск", str(exc))
            self._set_switch(False)
            return
        self._set_busy(True, "Запуск Nadejda…")

        def done(rc, output):
            self._set_busy(False)
            if rc == 0:
                self._toast("Nadejda запущена")
            else:
                self._set_switch(False)
                self._show_error("Не удалось запустить Nadejda", output)
            GLib.timeout_add(500, lambda: (self._refresh_status(force=True), False)[1])

        self._run_argv(argv, done)

    def _stop_engine(self) -> None:
        try:
            argv = (
                self._admin_systemctl("stop", UNIT)
                if systemd_unit_active()
                else self._admin_cli(["stop"])
            )
        except RuntimeError as exc:
            self._show_error("Остановка", str(exc))
            self._set_switch(True)
            return
        self._set_busy(True, "Остановка Nadejda…")

        def done(rc, output):
            self._set_busy(False)
            if rc == 0:
                self._toast("Nadejda остановлена")
            else:
                self._set_switch(True)
                self._show_error("Не удалось остановить Nadejda", output)
            GLib.timeout_add(500, lambda: (self._refresh_status(force=True), False)[1])

        self._run_argv(argv, done)

    # -- connectivity test --------------------------------------------------

    def _prepare_results(self) -> None:
        for row, _icon in self._rows.values():
            self.results_group.remove(row)
        self._rows.clear()
        self._test_ok = 0
        self.results_group.set_visible(True)
        for host in DEFAULT_TARGETS:
            row = Adw.ActionRow(title=host, subtitle="ожидание…")
            icon = Gtk.Image.new_from_icon_name("content-loading-symbolic")
            icon.add_css_class("host-wait")
            row.add_prefix(icon)
            self.results_group.add(row)
            self._rows[host] = (row, icon)

    def _update_result(self, result) -> None:
        host, ok, detail, elapsed = result
        entry = self._rows.get(host)
        if not entry:
            return
        row, icon = entry
        for css in ("host-ok", "host-fail", "host-wait"):
            icon.remove_css_class(css)
        icon.set_from_icon_name("emblem-ok-symbolic" if ok else "dialog-warning-symbolic")
        icon.add_css_class("host-ok" if ok else "host-fail")
        row.set_subtitle(f"{detail} · {elapsed:.2f} с")
        if ok:
            self._test_ok += 1

    def _on_test(self, *_args) -> None:
        if self._busy:
            return
        self._prepare_results()
        self._set_busy(True, "Проверка сайтов…")
        try:
            cfg = configmod.load(self.config_path)
        except Exception as exc:  # noqa: BLE001
            self._set_busy(False)
            self._show_error("Конфигурация", str(exc))
            return

        def worker():
            for host in DEFAULT_TARGETS:
                try:
                    result = test_hosts(cfg, [host], timeout=6.0)[0]
                except Exception as exc:  # noqa: BLE001
                    result = (host, False, f"{type(exc).__name__}: {exc}", 0.0)
                GLib.idle_add(self._update_result, result)
            GLib.idle_add(finish)

        def finish():
            self._set_busy(False)
            total = len(DEFAULT_TARGETS)
            self._toast(f"Доступно {self._test_ok} из {total} сайтов")

        threading.Thread(target=worker, daemon=True).start()

    # -- autotune -----------------------------------------------------------

    def _on_autotune(self, *_args) -> None:
        if self._busy:
            return
        if autotune_running():
            self._toast("Автоподбор уже идёт — дождитесь его окончания")
            return
        body = (
            "Nadejda остановится, переберёт стратегии (обычно 2–5 минут) и запустится "
            "снова. Проверяется не только TLS, но и реальная загрузка страниц, поэтому "
            "подбор может занять дольше. Интернет на это время может прерваться."
        )
        self._confirm(
            "Подобрать стратегию?",
            body,
            "Подобрать",
            self._start_autotune,
        )

    def _start_autotune(self) -> None:
        args = ["autotune", "--quick", "--save"]
        if systemd_unit_exists():
            args.append("--service")
        try:
            argv = self._admin_cli(args)
        except RuntimeError as exc:
            self._show_error("Автоподбор", str(exc))
            return
        self._last_task_lines = []
        self._set_busy(True, "Подбор стратегии…")

        def on_line(line: str) -> None:
            self._last_task_lines.append(line)
            self.task_label.set_text(line[:180])

        def done(rc, output):
            self._set_busy(False)
            self._reload_config()
            if rc == 0:
                best = ""
                for line in reversed(self._last_task_lines):
                    if "best strategy" in line.lower():
                        best = line.split(":", 1)[-1].strip()
                        break
                self._toast(f"Готово: {best}" if best else "Стратегия сохранена")
            else:
                self._show_error("Не удалось подобрать стратегию", output)
            GLib.timeout_add(700, lambda: (self._refresh_status(force=True), False)[1])

        self._run_stream(argv, on_line, done)

    # -- settings -----------------------------------------------------------

    def _load_settings(self) -> None:
        self._loading_settings = True
        try:
            try:
                index = self._strategy_names.index(self.cfg.strategy.name)
            except ValueError:
                index = 0
            self.strategy_row.set_selected(index)
            self._on_strategy_changed(self.strategy_row, None)

            try:
                scope_index = self._scope_values.index(self.cfg.general.scope)
            except ValueError:
                scope_index = 0
            self.scope_row.set_selected(scope_index)

            try:
                quic_index = self._quic_values.index(self.cfg.general.quic)
            except ValueError:
                quic_index = 0
            self.quic_row.set_selected(quic_index)

            try:
                udp_index = self._udp_names.index(self.cfg.udp.name)
            except ValueError:
                udp_index = 0
            self.udp_row.set_selected(udp_index)
            self._on_udp_changed(self.udp_row, None)

            self.sni_row.set_active(bool(self.cfg.general.sni_filter))
            self.dns_row.set_active(bool(self.cfg.general.dns))
        finally:
            self._loading_settings = False

    def _on_strategy_changed(self, row: Adw.ComboRow, _pspec) -> None:
        index = row.get_selected()
        if 0 <= index < len(self._strategy_names):
            name = self._strategy_names[index]
            row.set_subtitle(describe(PRESETS[name]))

    def _on_udp_changed(self, row: Adw.ComboRow, _pspec) -> None:
        index = row.get_selected()
        if 0 <= index < len(self._udp_names):
            name = self._udp_names[index]
            row.set_subtitle(describe_udp(UDP_PRESETS[name]))

    def _on_save_settings(self, *_args) -> None:
        if self._busy:
            return
        strategy = self._strategy_names[self.strategy_row.get_selected()]
        udp_strategy = self._udp_names[self.udp_row.get_selected()]
        scope = self._scope_values[self.scope_row.get_selected()]
        quic = self._quic_values[self.quic_row.get_selected()]
        dns = self.dns_row.get_active()
        sni = self.sni_row.get_active()

        args: list[str] = ["set-config"]
        if strategy != self.cfg.strategy.name:
            args += ["--strategy", strategy]
        if udp_strategy != self.cfg.udp.name:
            args += ["--udp-strategy", udp_strategy]
        if scope != self.cfg.general.scope:
            args += ["--scope", scope]
        if quic != self.cfg.general.quic:
            args += ["--quic", quic]
        if dns != self.cfg.general.dns:
            args.append("--dns" if dns else "--no-dns")
        if sni != self.cfg.general.sni_filter:
            args.append("--sni-filter" if sni else "--no-sni-filter")

        if len(args) == 1:
            self._toast("Изменений нет")
            return
        if self._running:
            args.append("--restart")
        try:
            argv = self._admin_cli(args)
        except RuntimeError as exc:
            self._show_error("Настройки", str(exc))
            return
        self._set_busy(True, "Сохранение настроек…")

        def done(rc, output):
            self._set_busy(False)
            if rc == 0:
                self._reload_config()
                self._toast("Настройки сохранены")
            else:
                self._show_error("Не удалось сохранить настройки", output)
            GLib.timeout_add(700, lambda: (self._refresh_status(force=True), False)[1])

        self._run_argv(argv, done)

    def _reload_config(self) -> None:
        try:
            self.cfg = configmod.load(self.config_path)
        except Exception:  # noqa: BLE001
            return
        self._load_settings()
        self._refresh_status(force=True)

    # -- logs ---------------------------------------------------------------

    def _refresh_logs(self) -> None:
        if self._log_buffer is None:
            return
        try:
            text = LOGFILE.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            text = (
                f"Не удалось прочитать {LOGFILE}: {exc}\n\n"
                "Убедитесь, что Nadejda установлена и запускалась хотя бы один раз."
            )
        lines = text.splitlines()
        tail = lines[-500:] if lines else ["(журнал пуст)"]
        self._log_buffer.set_text("\n".join(tail))
        GLib.idle_add(self._scroll_logs_to_end)

    def _scroll_logs_to_end(self) -> bool:
        if self._log_view is None or self._log_buffer is None:
            return False
        end = self._log_buffer.get_end_iter()
        self._log_view.scroll_to_iter(end, 0.0, False, 0.0, 1.0)
        return False

    def _auto_logs_tick(self) -> bool:
        if self.auto_logs.get_active() and self.stack.get_visible_child_name() == "logs":
            self._refresh_logs()
        return True

    def _on_page_changed(self, *_args) -> None:
        if self.stack.get_visible_child_name() == "logs":
            self._refresh_logs()

    def _on_open_logs(self, *_args) -> None:
        self.stack.set_visible_child_name("logs")
        self._refresh_logs()


class NadejdaApp(Adw.Application):
    def __init__(self, config_path: Path):
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.config_path = config_path
        self.window: NadejdaWindow | None = None

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        Gtk.Window.set_default_icon_name("nadejda")
        display = Gdk.Display.get_default()
        if display is not None:
            provider = Gtk.CssProvider()
            try:
                provider.load_from_data(CSS.encode("utf-8"))
                Gtk.StyleContext.add_provider_for_display(
                    display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                )
            except GLib.Error:
                pass

        about = Gio.SimpleAction.new("about", None)
        about.connect("activate", self._on_about)
        self.add_action(about)
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self.quit())
        self.add_action(quit_action)

    def do_activate(self) -> None:
        if self.window is None:
            self.window = NadejdaWindow(self, self.config_path)
        self.window.present()

    def _on_about(self, *_args) -> None:
        about = Adw.AboutDialog()
        about.set_application_name("Nadejda")
        about.set_application_icon("nadejda")
        about.set_version(__version__)
        about.set_comments(
            "Обход DPI для GitHub, YouTube, Spotify, SoundCloud и Discord.\n"
            "nftables + NFQUEUE + собственный движок рассинхронизации TCP."
        )
        about.present(self.window)


def run_gui(config_path: str | Path | None = None) -> int:
    path = _resolve_config(config_path)
    GLib.set_prgname("nadejda")
    GLib.set_application_name("Nadejda")
    app = NadejdaApp(path)
    try:
        return app.run([sys.argv[0]])
    except Exception as exc:  # noqa: BLE001
        print(f"nadejda: GUI failed: {exc}", file=sys.stderr)
        return 1
