# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the standalone Windows executables.

Build on Windows (or under Wine):

    pyinstaller --noconfirm --clean windows\\nadejda.spec

Outputs ``dist\\Nadejda.exe`` (GUI) and ``dist\\nadejda-win.exe`` (CLI).
Both are single-file, 64-bit, and request administrator rights in their
manifest, because opening the WinDivert driver requires elevation.
"""

import os

import pydivert

ROOT = os.path.dirname(SPECPATH)
PYDIVERT_DIR = os.path.dirname(pydivert.__file__)
WINDIVERT_DIR = os.path.join(PYDIVERT_DIR, "windivert_dll")

binaries = [
    (os.path.join(WINDIVERT_DIR, "WinDivert64.dll"), "pydivert/windivert_dll"),
]

datas = [
    # WinDivert loads the driver from the directory that holds the DLL.
    (os.path.join(WINDIVERT_DIR, "WinDivert64.sys"), "pydivert/windivert_dll"),
    # First-run default for %ProgramData%/Nadejda/config.toml.
    (os.path.join(ROOT, "config", "config.toml"), "config"),
]

hiddenimports = [
    "pydivert",
    "pydivert.windivert",
    "pydivert.windivert_dll",
    "pydivert.packet",
    "pydivert.packet.ip",
    "pydivert.packet.tcp",
    "pydivert.packet.udp",
    "pydivert.packet.icmp",
    "pydivert.consts",
    "pydivert.util",
    "nadejda.win.cli",
    "nadejda.win.divert",
    "nadejda.win.engine",
    "nadejda.win.gui",
]


def analyse(entry):
    return Analysis(
        [os.path.join(ROOT, entry)],
        pathex=[ROOT],
        binaries=binaries,
        datas=datas,
        hiddenimports=hiddenimports,
        hookspath=[],
        runtime_hooks=[],
        excludes=[],
        noarchive=False,
        optimize=0,
    )


gui_analysis = analyse("windows/entry_gui.py")
gui_pyz = PYZ(gui_analysis.pure)
gui = EXE(
    gui_pyz,
    gui_analysis.scripts,
    gui_analysis.binaries,
    gui_analysis.datas,
    [],
    name="Nadejda",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=os.path.join(ROOT, "windows", "nadejda.ico"),
    uac_admin=True,
)

cli_analysis = analyse("windows/entry_cli.py")
cli_pyz = PYZ(cli_analysis.pure)
cli = EXE(
    cli_pyz,
    cli_analysis.scripts,
    cli_analysis.binaries,
    cli_analysis.datas,
    [],
    name="nadejda-win",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon=os.path.join(ROOT, "windows", "nadejda.ico"),
    uac_admin=True,
)
