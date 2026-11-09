"""Configuration loading and defaults."""

from __future__ import annotations

import dataclasses
import logging
import os
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .desync import PRESETS, UDP_PRESETS, Strategy, UDPStrategy

log = logging.getLogger(__name__)

DEFAULT_CONFIG = Path("/etc/nadejda/config.toml")
DEFAULT_MARK = 0x4E414445  # "NADE"
DEFAULT_QUEUE = 200

# Domains that are throttled/blocked by SNI in the regions Nadejda targets.
# Matching is done on exact names and on any subdomain.
BUILTIN_DOMAINS: dict[str, list[str]] = {
    "github": [
        "github.com",
        "githubusercontent.com",
        "githubassets.com",
        "github.io",
        "github.dev",
        "githubapp.com",
        "ghcr.io",
        "gist.github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "avatars.githubusercontent.com",
        "raw.githubusercontent.com",
        "api.github.com",
        "githubcopilot.com",
        "github-cloud.s3.amazonaws.com",
    ],
    "youtube": [
        "youtube.com",
        "youtu.be",
        "youtube-nocookie.com",
        "youtube.googleapis.com",
        "youtubei.googleapis.com",
        "ytimg.com",
        "ytstatic.com",
        "ggpht.com",
        "googlevideo.com",
        "gvt1.com",
        "gvt2.com",
        "googleusercontent.com",
        "googlesyndication.com",
        "doubleclick.net",
    ],
    "spotify": [
        "spotify.com",
        "spotifycdn.com",
        "spotifycdn.net",
        "scdn.co",
        "spotify.link",
        "spotifycharts.com",
        "spotify.design",
        "audio-ak.spotify.com",
        "api.spotify.com",
        "apresolve.spotify.com",
        "accounts.spotify.com",
        "open.spotify.com",
        "dealer.spotify.com",
        "spclient.wg.spotify.com",
        # Audio streams are served from Akamai/Edgesuite hosts that are not
        # subdomains of spotify.com; without these the player UI loads but
        # playback stalls.
        "audio-ak-spotify-com.akamaized.net",
        "audio4-ak.spotify.com.edgesuite.net",
        "audio-ak.spotify.com.edgesuite.net",
    ],
    "soundcloud": [
        "soundcloud.com",
        "soundcloud.cloud",
        "sndcdn.com",
        "soundcloud.app.goo.gl",
        "api.soundcloud.com",
        "api-v2.soundcloud.com",
        "api-auth.soundcloud.com",
        "dwt.soundcloud.com",
        "assets.web.soundcloud.cloud",
        "a-v2.sndcdn.com",
        "cf-media.sndcdn.com",
        "cf-hls-media.sndcdn.com",
        "cf-hls-opus.sndcdn.com",
        "i1.sndcdn.com",
        "i2.sndcdn.com",
        "i3.sndcdn.com",
        "i4.sndcdn.com",
        "m.soundcloud.com",
        "wis.sndcdn.com",
        "va.sndcdn.com",
    ],
    "chatgpt": [
        "chatgpt.com",
        "chat.openai.com",
        "openai.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "auth.openai.com",
        "api.openai.com",
        "cdn.oaistatic.com",
        "chatgpt.livekit.cloud",
        "openai.azure.com",
    ],
    "discord": [
        "discord.com",
        "discord.gg",
        "discord.co",
        "discord.dev",
        "discord.new",
        "discord.gift",
        "discord.gifts",
        "discord.store",
        "discord.status",
        "discord.design",
        "discord.media",
        "discordapp.com",
        "discordapp.net",
        "discordcdn.com",
        "discordactivities.com",
        "discordmerch.com",
        "discordpartygames.com",
        "discord-attachments-uploads-prd.storage.googleapis.com",
        "gateway.discord.gg",
        "cdn.discordapp.com",
        "media.discordapp.net",
    ],
}


@dataclass(slots=True)
class GeneralConfig:
    queue_num: int = DEFAULT_QUEUE
    fwmark: int = DEFAULT_MARK
    scope: str = "all"                 # "all" | "list"
    sni_filter: bool = True
    desync_unknown: bool = False       # desync ClientHellos without SNI (ECH)
    # What to do with QUIC (UDP/443): fragment Initial packets ("desync"),
    # reject them so apps fall back to TCP ("block"), or leave them alone.
    # block_quic is the legacy spelling, kept so old configs keep working.
    quic: str = "desync"               # "desync" | "block" | "off"
    block_quic: str = "all"            # deprecated: "all" | "list" | "off"
    dns: bool = True                   # transparent DNS proxy + redirect
    dns_port: int = 5353
    dns_upstreams: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    dns_fallback_udp: bool = True
    dns_cache_ttl: int = 3600
    dns_strip_aaaa: bool = False
    # Break TCP flows that the provider has silently black-holed.  When the
    # client retransmits identical bytes (a ClientHello or a request) several
    # times with no reply, the socket is reset so the application reconnects
    # at once instead of waiting for the 15-minute TCP timeout.
    stall_reset: bool = True
    # Zapret handles more than TCP/443: plain HTTP, alternative HTTPS ports
    # (Discord media uses 2053/2083/2087/2096/8443) and Discord voice /
    # screen-share UDP.  These lists drive the nftables rules and the engine.
    tcp_ports: list[int] = field(
        default_factory=lambda: [80, 443, 2053, 2083, 2087, 2096, 8443]
    )
    udp_voice_ports: list[str] = field(
        default_factory=lambda: ["19294-19344", "50000-50100"]
    )
    # How many data packets of a flow to desync (SYN is not counted).
    tcp_cutoff: int = 4
    # How many datagrams of a UDP flow to precede with a fake packet.
    udp_cutoff: int = 6
    # Zapret-style game filter: "off", "tcp", "udp" or "all".  It extends the
    # port rules to game_tcp_ports / game_udp_ports and applies the same
    # any-protocol desync.  Off by default, exactly like zapret.
    game_filter: str = "off"
    game_tcp_ports: str = "1024-65535"
    game_udp_ports: str = "1024-65535"
    refresh_seconds: int = 900
    log_level: str = "info"

    def validate(self) -> None:
        if self.scope not in ("all", "list"):
            raise ValueError("general.scope must be 'all' or 'list'")
        if self.quic not in ("desync", "block", "off"):
            raise ValueError("general.quic must be 'desync', 'block' or 'off'")
        if self.block_quic not in ("all", "list", "off"):
            raise ValueError("general.block_quic must be 'all', 'list' or 'off'")
        if not 1 <= self.queue_num <= 65535:
            raise ValueError("general.queue_num out of range")
        if not 1 <= self.dns_port <= 65535:
            raise ValueError("general.dns_port out of range")
        if not self.tcp_ports:
            raise ValueError("general.tcp_ports must not be empty")
        for port in self.tcp_ports:
            if not 1 <= int(port) <= 65535:
                raise ValueError(f"general.tcp_ports: bad port {port!r}")
        for item in self.udp_voice_ports:
            _validate_range(item, "general.udp_voice_ports")
        if not 0 <= self.tcp_cutoff <= 32:
            raise ValueError("general.tcp_cutoff must be between 0 and 32")
        if not 0 <= self.udp_cutoff <= 32:
            raise ValueError("general.udp_cutoff must be between 0 and 32")
        if self.game_filter not in ("off", "tcp", "udp", "all"):
            raise ValueError("general.game_filter must be 'off', 'tcp', 'udp' or 'all'")
        if self.game_filter in ("tcp", "all"):
            _validate_range(self.game_tcp_ports, "general.game_tcp_ports")
        if self.game_filter in ("udp", "all"):
            _validate_range(self.game_udp_ports, "general.game_udp_ports")


def _validate_range(value: str, name: str) -> None:
    text = str(value).strip()
    try:
        if "-" in text:
            low, high = text.split("-", 1)
            low_i, high_i = int(low), int(high)
            if not (1 <= low_i <= high_i <= 65535):
                raise ValueError
        elif not 1 <= int(text) <= 65535:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"{name}: bad port range {value!r}") from exc


@dataclass(slots=True)
class Config:
    general: GeneralConfig
    strategy: Strategy
    domains: list[str]
    path: Path
    udp: UDPStrategy = field(default_factory=UDPStrategy)
    # domain (suffix) -> TCP strategy name.  Some hosts need a different
    # desync: e.g. soundcloud.com resets the connection on its SNI, while its
    # CDN is more reliable with plain splitting.
    overrides: dict[str, str] = field(default_factory=dict)
    # Domains that must never be touched (banks, Steam, OS updates, ...).
    exclude: list[str] = field(default_factory=list)

    @property
    def mark(self) -> int:
        return self.general.fwmark


def _domains_from(data: dict) -> list[str]:
    domains: list[str] = []
    for values in BUILTIN_DOMAINS.values():
        domains.extend(values)
    for item in data.get("extra_domains", []) or []:
        domains.append(str(item).strip().lower().lstrip("."))
    extra_file = data.get("extra_file")
    if extra_file:
        path = Path(os.path.expanduser(str(extra_file)))
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    domains.append(line.lstrip("."))
        else:
            log.warning("extra hostlist %s not found", path)
    excluded = {str(x).lower() for x in data.get("exclude", []) or []}
    seen: set[str] = set()
    result: list[str] = []
    for domain in domains:
        if not domain or domain in excluded or domain in seen:
            continue
        seen.add(domain)
        result.append(domain)
    return result


def _exclude_from(data: dict) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in data.get("exclude", []) or []:
        domain = str(item).strip().lower().lstrip(".")
        if domain and domain not in seen:
            seen.add(domain)
            result.append(domain)
    return result


def load(path: str | Path | None = None) -> Config:
    cfg_path = Path(os.path.expanduser(str(path or os.environ.get("NADEJDA_CONFIG") or DEFAULT_CONFIG)))
    raw: dict = {}
    if cfg_path.is_file():
        with cfg_path.open("rb") as fh:
            raw = tomllib.load(fh)
    else:
        log.warning("config %s not found, using defaults", cfg_path)

    general_raw = dict(raw.get("general", {}))
    # Migrate the old block_quic setting only when the new key is absent.
    if "quic" not in general_raw and "block_quic" in general_raw:
        legacy = str(general_raw["block_quic"])
        if legacy == "off":
            general_raw["quic"] = "off"
        elif legacy in ("all", "list"):
            general_raw["quic"] = "block"
        log.info(
            "general.block_quic is deprecated; use general.quic = "
            "'desync'|'block'|'off' instead"
        )
    general = GeneralConfig(**general_raw)
    general.validate()

    desync_raw = dict(raw.get("desync", {}))
    preset_name = desync_raw.pop("strategy", "seqovl568")
    if preset_name in PRESETS:
        strategy = PRESETS[preset_name].clone()
    else:
        strategy = Strategy(name=preset_name)
    for key, value in desync_raw.items():
        if not hasattr(strategy, key):
            raise ValueError(f"unknown desync option: {key}")
        setattr(strategy, key, value)
    strategy.name = preset_name

    udp_raw = dict(raw.get("udp", {}))
    udp_name = udp_raw.pop("strategy", "quic_frag")
    if udp_name in UDP_PRESETS:
        udp = UDP_PRESETS[udp_name].clone()
    else:
        udp = UDPStrategy(name=udp_name)
    for key, value in udp_raw.items():
        if not hasattr(udp, key):
            raise ValueError(f"unknown udp option: {key}")
        setattr(udp, key, value)
    udp.name = udp_name
    if udp.mode not in ("frag", "fake", "off"):
        raise ValueError("udp.mode must be 'frag', 'fake' or 'off'")

    overrides: dict[str, str] = {}
    for domain, preset in dict(raw.get("overrides", {})).items():
        key = str(domain).strip().lower().lstrip(".")
        if not key:
            raise ValueError("overrides: empty domain")
        if preset not in PRESETS:
            raise ValueError(f"overrides: unknown strategy {preset!r} for {key}")
        overrides[key] = str(preset)

    domains = _domains_from(raw.get("hosts", {}))
    exclude = _exclude_from(raw.get("hosts", {}))
    return Config(
        general=general,
        strategy=strategy,
        domains=domains,
        path=cfg_path,
        udp=udp,
        overrides=overrides,
        exclude=exclude,
    )


def dump(cfg: Config) -> str:
    """Serialise the configuration back to TOML (used by autotune/install)."""
    lines = ["# Nadejda configuration", "", "[general]"]
    for f in dataclasses.fields(GeneralConfig):
        if f.name == "block_quic":  # superseded by general.quic
            continue
        value = getattr(cfg.general, f.name)
        lines.append(f"{f.name} = {_toml(value)}")
    lines += ["", "[desync]", f"strategy = {_toml(cfg.strategy.name)}"]
    for f in dataclasses.fields(Strategy):
        if f.name == "name":
            continue
        value = getattr(cfg.strategy, f.name)
        lines.append(f"{f.name} = {_toml(value)}")
    lines += ["", "[udp]", f"strategy = {_toml(cfg.udp.name)}"]
    for f in dataclasses.fields(UDPStrategy):
        if f.name == "name":
            continue
        value = getattr(cfg.udp, f.name)
        lines.append(f"{f.name} = {_toml(value)}")
    if cfg.overrides:
        lines += ["", "[overrides]"]
        for domain, preset in cfg.overrides.items():
            lines.append(f"{_toml(domain)} = {_toml(preset)}")
    lines += [
        "",
        "[hosts]",
        "extra_domains = []",
        'extra_file = ""',
        f"exclude = {_toml(cfg.exclude)}",
        "",
    ]
    return "\n".join(lines)


def _atomic_write(target: Path, text: str) -> None:
    """Replace ``target`` in one step.

    A service restart can happen right after a config update; with a plain
    ``write_text`` it may open a truncated file and silently fall back to the
    defaults (that is how a tuned strategy turned into ``seqovl568``).
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


_GENERATED_COMMENT = "# Nadejda: written by 'nadejda autotune --save'."


def _section_block(name: str, obj, comment: str = _GENERATED_COMMENT) -> list[str]:
    block = [comment, f"[{name}]", f"strategy = {_toml(obj.name)}"]
    for f in dataclasses.fields(obj):
        if f.name == "name":
            continue
        block.append(f"{f.name} = {_toml(getattr(obj, f.name))}")
    return block


def _replace_section(lines: list[str], name: str, block: list[str]) -> list[str]:
    header = f"[{name}]"
    start: int | None = None
    end: int | None = None
    for index, line in enumerate(lines):
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if stripped == header:
                start = index
            elif start is not None and end is None:
                end = index
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        return lines + block
    # Drop comments generated by previous saves, otherwise every autotune
    # run leaves another identical line above the section.
    while start > 0 and lines[start - 1].strip().startswith("# Nadejda: written by"):
        start -= 1
    end = len(lines) if end is None else end
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return lines[:start] + block + [""] + lines[end:]


def save(cfg: Config, path: str | Path | None = None) -> Path:
    """Write the strategies back, preserving the rest of a hand-edited config.

    Only ``[desync]`` and ``[udp]`` are regenerated, so comments in
    ``[general]`` and domain lists in ``[hosts]`` survive autotune.
    """
    target = Path(path) if path is not None else cfg.path
    if target is None:
        raise ValueError("config path is not set")
    desync_block = _section_block("desync", cfg.strategy)
    udp_block = _section_block("udp", cfg.udp)

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines() if target.is_file() else []
    lines = _replace_section(lines, "desync", desync_block)
    lines = _replace_section(lines, "udp", udp_block)

    _atomic_write(target, "\n".join(lines).rstrip() + "\n")
    return target


def write_updates(
    cfg: Config,
    general: dict[str, object] | None = None,
    strategy: str | None = None,
    udp: dict[str, object] | None = None,
    udp_strategy: str | None = None,
    overrides: dict[str, str] | None = None,
    path: str | Path | None = None,
) -> Path:
    """Apply a few option changes while keeping comments and unknown keys.

    ``general`` maps ``[general]`` keys (scope, quic, dns, ...) to new values.
    ``strategy``/``udp_strategy`` select presets and regenerate the matching
    section.  ``overrides`` replaces the per-domain TCP strategy table.
    """
    target = Path(path) if path is not None else cfg.path
    if target is None:
        raise ValueError("config path is not set")
    if strategy is not None and strategy not in PRESETS:
        raise ValueError(f"unknown strategy {strategy!r}")
    if udp_strategy is not None and udp_strategy not in UDP_PRESETS:
        raise ValueError(f"unknown UDP strategy {udp_strategy!r}")

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines() if target.is_file() else []
    if general:
        lines = _set_section(lines, "general", general)
    if udp:
        lines = _set_section(lines, "udp", udp)
    if overrides is not None:
        clean: dict[str, str] = {}
        for domain, preset in overrides.items():
            key = str(domain).strip().lower().lstrip(".")
            if not key:
                raise ValueError("overrides: empty domain")
            if preset not in PRESETS:
                raise ValueError(f"overrides: unknown strategy {preset!r} for {key}")
            clean[key] = preset
        cfg.overrides = clean
        block = ["[overrides]"] + [
            f"{_toml(domain)} = {_toml(preset)}" for domain, preset in clean.items()
        ]
        lines = _replace_section(lines, "overrides", block)
    _atomic_write(target, "\n".join(lines).rstrip() + "\n")
    if strategy is not None:
        cfg.strategy = PRESETS[strategy].clone()
    if udp_strategy is not None:
        cfg.udp = UDP_PRESETS[udp_strategy].clone()
    # Explicit tweaks win over the preset defaults.
    for key, value in (udp or {}).items():
        setattr(cfg.udp, key, value)
    if strategy is not None or udp_strategy is not None:
        save(cfg, target)
    return target


def _set_section(lines: list[str], section: str, updates: dict[str, object]) -> list[str]:
    header = f"[{section}]"
    start: int | None = None
    end: int | None = None
    for index, line in enumerate(lines):
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if stripped == header:
                start = index
            elif start is not None and end is None:
                end = index
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(header)
        start = len(lines) - 1
        end = len(lines)
    end = len(lines) if end is None else end

    for key, value in updates.items():
        rendered = f"{key} = {_toml(value)}"
        found: int | None = None
        for index in range(start + 1, end):
            code = lines[index].split("#", 1)[0].strip()
            if "=" in code and code.split("=", 1)[0].strip() == key:
                found = index
                break
        if found is not None:
            comment = ""
            if "#" in lines[found]:
                comment = "  #" + lines[found].split("#", 1)[1]
            lines[found] = rendered + comment
        else:
            insert = end
            while insert - 1 > start and not lines[insert - 1].strip():
                insert -= 1
            lines.insert(insert, rendered)
            end += 1
    return lines


def _toml(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
