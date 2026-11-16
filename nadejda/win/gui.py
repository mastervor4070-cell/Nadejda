"""Tkinter GUI for Nadejda for Windows.

The engine runs in a background thread inside this process, so Start/Stop are
instant.  Opening the WinDivert driver needs administrator rights: if the GUI
was started normally it offers a "Run as administrator" button that relaunches
itself elevated (one UAC prompt).
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import queue
import sys
import threading
import tkinter as tk
import types
from pathlib import Path
from tkinter import messagebox, ttk

from .. import __version__
from .. import config as configmod
from ..desync import PRESETS, UDP_PRESETS
from . import cli
from .divert import WinDivertError, WinDivertHandle, is_admin
from .engine import WinEngine

log = logging.getLogger("nadejda.win.gui")

QUIC_MODES = ("desync", "block", "off")


class _QueueHandler(logging.Handler):
    def __init__(self, sink: "queue.Queue[str]"):
        super().__init__()
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink.put_nowait(self.format(record))
        except Exception:
            pass


class App:
    def __init__(self, root: tk.Tk, config_path: Path):
        self.root = root
        self.config_path = Path(config_path)
        self.cfg = configmod.load(self.config_path)
        self.engine: WinEngine | None = None
        self.thread: threading.Thread | None = None
        self.messages: "queue.Queue[str]" = queue.Queue()
        self._build()
        self._install_logging()
        self._poll()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    # -- layout -------------------------------------------------------------

    def _build(self) -> None:
        self.root.title(f"Nadejda {__version__} for Windows")
        self.root.geometry("760x560")
        self.root.minsize(620, 460)

        top = ttk.Frame(self.root, padding=12)
        top.pack(fill="x")

        self.status = tk.StringVar(value="stopped")
        self.status_label = tk.Label(
            top, textvariable=self.status, anchor="w", font=("Segoe UI", 12, "bold")
        )
        self.status_label.grid(row=0, column=0, sticky="w")

        self.admin_label = ttk.Label(top, text="", foreground="#a33")
        self.admin_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))
        self.elevate_button = ttk.Button(
            top, text="Run as administrator", command=self._elevate
        )
        self.elevate_button.grid(row=1, column=3, sticky="e", pady=(4, 0))
        if is_admin():
            self.admin_label.configure(text="administrator: yes", foreground="#276")
            self.elevate_button.state(["disabled"])
        else:
            self.admin_label.configure(
                text="administrator: no — WinDivert cannot start without elevation"
            )

        options = ttk.LabelFrame(self.root, text="Strategy", padding=10)
        options.pack(fill="x", padx=12, pady=(0, 8))

        ttk.Label(options, text="TCP:").grid(row=0, column=0, sticky="w")
        self.strategy_var = tk.StringVar(value=self.cfg.strategy.name)
        self.strategy_box = ttk.Combobox(
            options,
            textvariable=self.strategy_var,
            values=sorted(PRESETS),
            state="readonly",
            width=34,
        )
        self.strategy_box.grid(row=0, column=1, sticky="w", padx=(6, 16))

        ttk.Label(options, text="UDP:").grid(row=0, column=2, sticky="w")
        self.udp_var = tk.StringVar(value=self.cfg.udp.name)
        self.udp_box = ttk.Combobox(
            options,
            textvariable=self.udp_var,
            values=sorted(UDP_PRESETS),
            state="readonly",
            width=20,
        )
        self.udp_box.grid(row=0, column=3, sticky="w", padx=6)

        ttk.Label(options, text="QUIC:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.quic_var = tk.StringVar(value=self.cfg.general.quic)
        self.quic_box = ttk.Combobox(
            options,
            textvariable=self.quic_var,
            values=QUIC_MODES,
            state="readonly",
            width=12,
        )
        self.quic_box.grid(row=1, column=1, sticky="w", padx=(6, 16), pady=(8, 0))

        self.config_label = ttk.Label(options, text=str(self.config_path), foreground="#666")
        self.config_label.grid(row=1, column=2, columnspan=2, sticky="w", pady=(8, 0))

        buttons = ttk.Frame(self.root, padding=(12, 0))
        buttons.pack(fill="x")
        self.start_button = ttk.Button(buttons, text="Start", command=self._start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop", command=self._stop)
        self.stop_button.pack(side="left", padx=6)
        ttk.Button(buttons, text="Apply & save", command=self._apply).pack(
            side="left", padx=6
        )
        ttk.Button(buttons, text="Test", command=self._test).pack(side="left", padx=6)
        ttk.Button(buttons, text="Open folder", command=self._open_folder).pack(
            side="left", padx=6
        )
        self.stop_button.state(["disabled"])

        stats = ttk.LabelFrame(self.root, text="Traffic", padding=10)
        stats.pack(fill="x", padx=12, pady=8)
        self.stat_vars: dict[str, tk.StringVar] = {}
        keys = [
            ("seen", "packets"),
            ("desynced", "TCP hello"),
            ("data_desynced", "TCP data"),
            ("udp_desynced", "UDP"),
            ("passed", "passed"),
            ("errors", "errors"),
        ]
        for column, (key, label) in enumerate(keys):
            var = tk.StringVar(value="0")
            self.stat_vars[key] = var
            ttk.Label(stats, text=label, foreground="#666").grid(
                row=0, column=column, sticky="w", padx=(0, 12)
            )
            ttk.Label(stats, textvariable=var, font=("Consolas", 12)).grid(
                row=1, column=column, sticky="w", padx=(0, 12)
            )

        log_frame = ttk.LabelFrame(self.root, text="Log", padding=6)
        log_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.log_text = tk.Text(log_frame, height=12, wrap="word", state="disabled")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _install_logging(self) -> None:
        handler = _QueueHandler(self.messages)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        root.addHandler(handler)

    # -- actions ------------------------------------------------------------

    def _start(self) -> None:
        if self.engine is not None:
            return
        if not is_admin():
            messagebox.showerror(
                "Administrator rights required",
                "WinDivert needs administrator rights.\n"
                "Use the “Run as administrator” button and press Start again.",
            )
            return
        try:
            self.cfg = configmod.load(self.config_path)
            self.cfg.strategy = PRESETS[self.strategy_var.get()].clone()
            self.cfg.udp = UDP_PRESETS[self.udp_var.get()].clone()
            self.cfg.general.quic = self.quic_var.get()
            engine = WinEngine(self.cfg, status_path=cli._status_path())
            # Open the handle here, not in the worker thread, so a driver or
            # permission error is reported by the Start button instead of
            # disappearing into the thread.
            handle = WinDivertHandle(engine.filter)
            handle.open()
            engine.handle = handle
            self.thread = engine.start()
        except (WinDivertError, ValueError, OSError) as exc:
            messagebox.showerror("Cannot start Nadejda", str(exc))
            return
        self.engine = engine
        self._set_running(True)
        self._log(f"started: {self.cfg.strategy.name} / {self.cfg.udp.name}")

    def _stop(self) -> None:
        engine, self.engine = self.engine, None
        thread, self.thread = self.thread, None
        if engine is not None:
            engine.stop()
            if thread is not None:
                thread.join(timeout=2.0)
            self._log("stopped")
        self._set_running(False)

    def _apply(self) -> None:
        try:
            configmod.write_updates(
                self.cfg,
                general={"quic": self.quic_var.get()},
                strategy=self.strategy_var.get(),
                udp_strategy=self.udp_var.get(),
            )
        except (OSError, ValueError) as exc:
            messagebox.showerror("Cannot save configuration", str(exc))
            return
        if self.engine is not None:
            self.engine.set_strategy(self.strategy_var.get())
            self.engine.set_udp_strategy(self.udp_var.get())
            self.engine.general.quic = self.quic_var.get()
        self._log("configuration saved")

    def _test(self) -> None:
        args = types.SimpleNamespace(config=str(self.config_path))
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                code = cli.cmd_test(args)
        except SystemExit as exc:
            code = int(exc.code or 1)
        self._log(buffer.getvalue().rstrip())
        self._log("test passed" if code == 0 else "test failed")

    def _open_folder(self) -> None:
        folder = self.config_path.parent
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                import subprocess

                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as exc:
            messagebox.showerror("Cannot open folder", str(exc))

    def _elevate(self) -> None:
        if os.name != "nt":
            messagebox.showinfo("Windows only", "Elevation is only needed on Windows.")
            return
        import ctypes

        python = Path(sys.executable)
        pythonw = python.with_name("pythonw.exe")
        executable = pythonw if pythonw.is_file() else python
        params = f'-m nadejda.win gui --config "{self.config_path}"'
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", str(executable), params, None, 1
        )
        if result <= 32:
            messagebox.showerror("Elevation failed", "The UAC prompt was cancelled.")
            return
        self.root.destroy()

    # -- helpers ------------------------------------------------------------

    def _set_running(self, running: bool) -> None:
        self.status.set("running" if running else "stopped")
        self.status_label.configure(fg="#276" if running else "#444")
        if running:
            self.start_button.state(["disabled"])
            self.stop_button.state(["!disabled"])
        else:
            self.start_button.state(["!disabled"])
            self.stop_button.state(["disabled"])

    def _log(self, text: str) -> None:
        if not text:
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll(self) -> None:
        try:
            while True:
                self._log(self.messages.get_nowait())
        except queue.Empty:
            pass
        engine = self.engine
        if engine is not None:
            try:
                snapshot = engine.stats_snapshot()
            except Exception:
                snapshot = None
            if snapshot is not None:
                for key, var in self.stat_vars.items():
                    var.set(str(snapshot["stats"].get(key, 0)))
        self.root.after(500, self._poll)

    def _close(self) -> None:
        if self.engine is not None:
            if not messagebox.askyesno("Quit", "Nadejda is running. Stop it and quit?"):
                return
            self._stop()
        self.root.destroy()


def main(config_path: str | Path | None = None) -> int:
    path = Path(config_path) if config_path else cli.ensure_config()
    if not path.is_file():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Configuration not found",
            f"{path}\n\nRun windows\\install.ps1 first.",
        )
        root.destroy()
        return 1
    root = tk.Tk()
    App(root, path)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
