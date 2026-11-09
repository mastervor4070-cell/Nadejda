#!/usr/bin/env python3
"""Config editing tests: comments survive, values actually change.

Runs as the current user against a temporary copy of the shipped config, so no
root privileges and no system changes are needed.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nadejda import config as configmod  # noqa: E402
from nadejda.desync import PRESETS  # noqa: E402
from nadejda.engine import Engine  # noqa: E402

FAILED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"ok   {name}")
    else:
        FAILED += 1
        print(f"FAIL {name}" + (f": {detail}" if detail else ""))


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.toml"
        path.write_text((ROOT / "config" / "config.toml").read_text(encoding="utf-8"), encoding="utf-8")
        before = path.read_text(encoding="utf-8")

        cfg = configmod.load(path)
        original_strategy = cfg.strategy.name

        # --- shipped defaults -------------------------------------------------
        check("defaults: quic mode", cfg.general.quic == "desync")
        check("defaults: udp strategy", cfg.udp.name == "quic_frag")
        check("defaults: udp split", cfg.udp.split == 64)
        check("defaults: force-TCP list", bool(cfg.udp.force_tcp_domains))
        check(
            "defaults: soundcloud override",
            cfg.overrides.get("soundcloud.com") == "fake_split_goodsum_ttl3_disorder",
        )

        # --- general keys are rewritten, comments and other sections stay -----
        configmod.write_updates(
            cfg,
            {"scope": "list", "block_quic": "off", "dns": False, "sni_filter": False},
        )
        after = path.read_text(encoding="utf-8")
        check("general: comment block preserved", "# Номер очереди NFQUEUE" in after)
        check("general: unrelated key untouched", "queue_num = 200" in after)
        check("general: comment kept on edited key", 'scope = "list"' in after and "#" in after)
        check("general: other sections preserved", "[hosts]" in after and "extra_domains = []" in after)

        reloaded = configmod.load(path)
        check("general: scope saved", reloaded.general.scope == "list")
        check("general: block_quic saved", reloaded.general.block_quic == "off")
        check("general: dns saved", reloaded.general.dns is False)
        check("general: sni_filter saved", reloaded.general.sni_filter is False)
        check("general: strategy untouched", reloaded.strategy.name == original_strategy)

        # --- strategy change regenerates [desync] only ------------------------
        new_strategy = "multisplit" if original_strategy != "multisplit" else "split1"
        configmod.write_updates(reloaded, strategy=new_strategy)
        after_strategy = path.read_text(encoding="utf-8")
        final = configmod.load(path)
        check("strategy: applied", final.strategy.name == new_strategy)
        check("strategy: preset fields match", final.strategy == PRESETS[new_strategy])
        check("strategy: [hosts] still present", "[hosts]" in after_strategy)
        check("strategy: [general] still present", "[general]" in after_strategy)
        check("strategy: no duplicated [desync]", after_strategy.count("[desync]") == 1)

        # --- CLI set-config ---------------------------------------------------
        path.write_text(before, encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "run.py"),
                "--config",
                str(path),
                "set-config",
                "--scope",
                "list",
                "--block-quic",
                "list",
                "--quic",
                "desync",
                "--udp-strategy",
                "quic_frag_early",
                "--udp-split",
                "96",
                "--no-udp-disorder",
                "--override",
                "example.org=split_sni",
                "--no-dns",
                "--strategy",
                "multisplit",
            ],
            capture_output=True,
            text=True,
        )
        check("cli: set-config exit 0", proc.returncode == 0, proc.stdout + proc.stderr)
        cli_cfg = configmod.load(path)
        check("cli: scope", cli_cfg.general.scope == "list")
        check("cli: block_quic", cli_cfg.general.block_quic == "list")
        check("cli: dns off", cli_cfg.general.dns is False)
        check("cli: quic mode", cli_cfg.general.quic == "desync")
        check("cli: udp strategy", cli_cfg.udp.name == "quic_frag_early")
        check("cli: udp split", cli_cfg.udp.split == 96)
        check("cli: udp disorder", cli_cfg.udp.disorder is False)
        check("cli: strategy", cli_cfg.strategy.name == "multisplit")
        check(
            "cli: override kept",
            cli_cfg.overrides.get("soundcloud.com") == "fake_split_goodsum_ttl3_disorder",
        )
        check("cli: override added", cli_cfg.overrides.get("example.org") == "split_sni")
        cli_text = path.read_text(encoding="utf-8")
        check("cli: comments kept", "# Nadejda — конфигурация по умолчанию." in cli_text)
        check("cli: single [udp] section", cli_text.count("[udp]") == 1)
        check("cli: single [overrides] section", cli_text.count("[overrides]") == 1)

        # --- engine picks the override by SNI suffix --------------------------
        engine = Engine(cli_cfg)
        check(
            "engine: override applies to subdomain",
            engine._select_strategy("api-v2.soundcloud.com")[0].name
            == "fake_split_goodsum_ttl3_disorder",
        )
        check(
            "engine: override applies to apex",
            engine._select_strategy("soundcloud.com")[0].name
            == "fake_split_goodsum_ttl3_disorder",
        )
        check(
            "engine: youtube override",
            engine._select_strategy("www.youtube.com")[0].name
            == "fake_split_goodsum_ttl3_disorder",
        )
        check(
            "engine: global strategy for other hosts",
            engine._select_strategy("github.com")[0].name == "multisplit",
        )

        # --- legacy block_quic still migrates --------------------------------
        legacy = Path(tmp) / "legacy.toml"
        legacy.write_text('[general]\nblock_quic = "off"\n', encoding="utf-8")
        legacy_cfg = configmod.load(legacy)
        check("legacy: block_quic -> quic", legacy_cfg.general.quic == "off")

        # --- invalid value is rejected ---------------------------------------
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "run.py"),
                "--config",
                str(path),
                "set-config",
                "--scope",
                "everything",
            ],
            capture_output=True,
            text=True,
        )
        check("cli: invalid scope rejected", proc.returncode != 0)

        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "run.py"),
                "--config",
                str(path),
                "set-config",
                "--override",
                "example.org=not-a-strategy",
            ],
            capture_output=True,
            text=True,
        )
        check("cli: invalid override rejected", proc.returncode != 0)

    if FAILED:
        print(f"\n{FAILED} check(s) failed")
        return 1
    print("\nconfig tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
