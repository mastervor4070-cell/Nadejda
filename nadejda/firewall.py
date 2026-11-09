"""nftables integration: transparent redirection into NFQUEUE + DNS redirect."""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)

TABLE = "nadejda"

# QUIC blocking must not cut Discord voice/screen-share: WebRTC uses TURN over
# UDP 443, and Discord relays through Cloudflare (Cloudflare Calls).  Discord
# media servers observed in Warsaw live in 104.29.148.0/24 and 104.29.149.0/24;
# blocking UDP/443 there made RTC connections time out and screen shares stay
# black.  The whole 104.28.0.0/14 block plus Cloudflare's published ranges are
# exempt now.  YouTube (Google) is not in these ranges, so the QUIC block still
# forces its traffic onto TCP where the desync works.
QUIC_ALLOW4 = (
    # Cloudflare, https://www.cloudflare.com/ips-v4
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    # Cloudflare Calls / Discord voice relays (not in the published list).
    "104.28.0.0/14",
)
QUIC_ALLOW6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

# Google/YouTube address space.  YouTube QUIC is often blocked deeper than the
# first IP fragment (the provider reassembles or drops it per destination), so
# rejecting UDP/443 here makes clients fall back to TCP immediately.  TCP is
# still desynchronised by the normal strategy.  These are broad Google ranges
# on purpose: YouTube rotates addresses, and a resolved-domain set alone is
# always a step behind.
QUIC_FORCE_TCP4 = (
    "23.236.48.0/20",
    "23.251.128.0/19",
    "64.233.160.0/19",
    "66.102.0.0/20",
    "66.249.80.0/20",
    "72.14.192.0/18",
    "74.125.0.0/16",
    "108.177.0.0/17",
    "142.250.0.0/15",
    "172.217.0.0/16",
    "172.253.0.0/16",
    "173.194.0.0/16",
    "209.85.128.0/17",
    "216.58.192.0/19",
    "216.239.32.0/19",
)
QUIC_FORCE_TCP6 = (
    "2404:6800::/32",
    "2607:f8b0::/32",
    "2800:3f0::/32",
    "2a00:1450::/32",
    "2c0f:fb50::/32",
)


def _merge_networks(base: tuple[str, ...], extra: list[str]) -> list[str]:
    """Merge CIDR strings/addresses into a non-overlapping interval list."""
    networks = []
    for item in (*base, *extra):
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            log.warning("ignoring invalid address %r", item)
    if not networks:
        return []
    version = networks[0].version
    same = [net for net in networks if net.version == version]
    return [str(net) for net in ipaddress.collapse_addresses(same)]


class FirewallError(RuntimeError):
    pass


@dataclass(slots=True)
class FirewallConfig:
    queue_num: int
    mark: int
    scope: str = "all"          # all | list
    quic: str = "off"           # desync | block | off
    block_quic: str = "off"     # legacy; used only when quic == "block"
    quic_force_tcp: bool = False  # reject UDP/443 to resolved force-TCP hosts
    dns: bool = True
    dns_port: int = 5353
    desync_port: int = 443      # legacy, superseded by tcp_ports
    tcp_ports: tuple[int, ...] = (80, 443, 2053, 2083, 2087, 2096, 8443)
    udp_voice_ports: tuple[str, ...] = ("19294-19344", "50000-50100")
    tcp_cutoff: int = 4
    udp_cutoff: int = 6
    game_filter: str = "off"    # off | tcp | udp | all
    game_tcp_ports: str = "1024-65535"
    game_udp_ports: str = "1024-65535"


def _port_spec(values) -> str:
    items = [str(item).strip() for item in values if str(item).strip()]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return "{ " + ", ".join(items) + " }"


class Firewall:
    def __init__(self, cfg: FirewallConfig):
        self.cfg = cfg
        self.nft = shutil.which("nft")
        if not self.nft:
            raise FirewallError("nftables is not installed (package 'nftables')")

    # -- helpers ------------------------------------------------------------

    def _run(self, script: str, *, check: bool = True) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            [self.nft, "-f", "-"],
            input=script,
            capture_output=True,
            text=True,
        )
        if check and proc.returncode != 0:
            raise FirewallError(f"nft failed: {proc.stderr.strip() or proc.stdout.strip()}")
        return proc

    @property
    def table_spec(self) -> str:
        return f"inet {TABLE}"

    # -- lifecycle ----------------------------------------------------------

    def build_ruleset(self) -> str:
        c = self.cfg
        lines = [
            f"table inet {TABLE} {{",
            "    set targets4 { type ipv4_addr; flags interval; }",
            "    set targets6 { type ipv6_addr; flags interval; }",
        ]
        if c.quic == "block" and c.block_quic == "all":
            allow4 = ", ".join(QUIC_ALLOW4)
            allow6 = ", ".join(QUIC_ALLOW6)
            lines += [
                f"    set quic_allow4 {{ type ipv4_addr; flags interval; elements = {{ {allow4} }} }}",
                f"    set quic_allow6 {{ type ipv6_addr; flags interval; elements = {{ {allow6} }} }}",
            ]
        if c.quic == "desync" and c.quic_force_tcp:
            lines += [
                "    set quic_block4 { type ipv4_addr; flags interval; }",
                "    set quic_block6 { type ipv6_addr; flags interval; }",
            ]
        lines += [
            "    chain out {",
            "        type filter hook output priority -150; policy accept;",
            f"        meta mark 0x{c.mark:x} return",
        ]
        # QUIC handling:
        #   desync — queue Initial packets and fragment them at the IP layer.
        #            The endpoint reassembles the datagram, a DPI that does not
        #            reassemble only sees a truncated first fragment.
        #   block  — reject QUIC so browsers fall back to TCP (legacy mode).
        #   off    — leave UDP/443 alone.
        # Voice/TURN destinations stay exempt in block mode, otherwise WebRTC
        # screen sharing breaks.
        if c.quic == "block" and c.block_quic == "all":
            lines.append("        ip daddr @quic_allow4 udp dport 443 counter accept")
            lines.append("        ip6 daddr @quic_allow6 udp dport 443 counter accept")
            lines.append("        udp dport 443 counter reject")
        elif c.quic == "block":
            lines.append("        ip daddr @targets4 udp dport 443 counter reject")
            lines.append("        ip6 daddr @targets6 udp dport 443 counter reject")
        elif c.quic == "desync":
            if c.quic_force_tcp:
                lines.append(
                    "        ip daddr @quic_block4 udp dport 443 counter reject"
                )
                lines.append(
                    "        ip6 daddr @quic_block6 udp dport 443 counter reject"
                )
            quic_limit = max(1, int(c.udp_cutoff))
            if c.scope == "all":
                lines.append(
                    "        udp dport 443 ct original packets "
                    f"<= {quic_limit} meta length > 200 counter "
                    f"queue num {c.queue_num} bypass"
                )
            else:
                lines.append(
                    "        ip daddr @targets4 udp dport 443 ct original packets "
                    f"<= {quic_limit} meta length > 200 counter "
                    f"queue num {c.queue_num} bypass"
                )
                lines.append(
                    "        ip6 daddr @targets6 udp dport 443 ct original packets "
                    f"<= {quic_limit} meta length > 200 counter "
                    f"queue num {c.queue_num} bypass"
                )

        # Discord voice / screen share.  Like zapret's
        # --filter-udp=19294-19344,50000-50100 rule there is no cutoff here:
        # every datagram gets a fake before it, otherwise a long screen share
        # loses protection after the first few packets.
        if c.udp_voice_ports:
            voice_spec = _port_spec(c.udp_voice_ports)
            lines.append(
                f"        udp dport {voice_spec} counter "
                f"queue num {c.queue_num} bypass"
            )
        if c.game_filter in ("udp", "all") and c.udp_cutoff:
            lines.append(
                f"        udp dport {c.game_udp_ports} ct original packets "
                f"<= {max(1, int(c.udp_cutoff))} counter "
                f"queue num {c.queue_num} bypass"
            )

        # TCP: HTTP, HTTPS and the alternative HTTPS ports used by Discord
        # media.  Only the first few packets of a flow are queued, which is
        # what zapret's --dpi-desync-cutoff does; this keeps large downloads
        # out of the userspace engine.
        tcp_spec = _port_spec(c.tcp_ports)
        # ct counts SYN, pure ACKs, the two segments of a large ClientHello
        # and every packet we inject ourselves (the fake decoys and the
        # overlap segments all traverse OUTPUT).  Leave enough headroom for
        # the first data packet to reach the engine as well.  Small tail
        # segments must reach the queue too, so there is deliberately no
        # length filter here.
        tcp_limit = max(1, int(c.tcp_cutoff) + 12)
        if c.scope == "all":
            lines.append(
                f"        tcp dport {tcp_spec} ct original packets <= {tcp_limit} "
                f"counter queue num {c.queue_num} bypass"
            )
        else:
            lines.append(
                f"        ip daddr @targets4 tcp dport {tcp_spec} "
                f"ct original packets <= {tcp_limit} counter "
                f"queue num {c.queue_num} bypass"
            )
            lines.append(
                f"        ip6 daddr @targets6 tcp dport {tcp_spec} "
                f"ct original packets <= {tcp_limit} counter "
                f"queue num {c.queue_num} bypass"
            )
        if c.game_filter in ("tcp", "all"):
            lines.append(
                f"        tcp dport {c.game_tcp_ports} ct original packets "
                f"<= {tcp_limit} counter queue num {c.queue_num} bypass"
            )
        lines.append("    }")
        if c.dns:
            # 'redirect' is a NAT statement: it must live in a nat chain.
            # The mark check keeps our own DNS-over-TLS/UDP packets out.
            lines += [
                "    chain dnsnat {",
                "        type nat hook output priority -150; policy accept;",
                f"        meta mark 0x{c.mark:x} return",
                f"        udp dport 53 redirect to :{c.dns_port}",
                f"        tcp dport 53 redirect to :{c.dns_port}",
                "    }",
            ]
        lines += ["}", ""]
        return "\n".join(lines)

    def apply(self) -> None:
        self.remove(quiet=True)
        script = self.build_ruleset()
        log.debug("applying ruleset:\n%s", script)
        self._run(script)
        log.info("nftables table inet %s installed", TABLE)

    def remove(self, *, quiet: bool = False) -> None:
        proc = subprocess.run(
            [self.nft, "delete", "table", "inet", TABLE], capture_output=True, text=True
        )
        if proc.returncode != 0 and not quiet:
            raise FirewallError(proc.stderr.strip())
        if proc.returncode == 0:
            log.info("nftables table inet %s removed", TABLE)

    def exists(self) -> bool:
        proc = subprocess.run(
            [self.nft, "list", "table", "inet", TABLE], capture_output=True, text=True
        )
        return proc.returncode == 0

    def update_sets(
        self,
        ipv4: list[str],
        ipv6: list[str],
        force4: list[str] | None = None,
        force6: list[str] | None = None,
    ) -> None:
        need_targets = self.cfg.scope == "list" or (
            self.cfg.quic == "block" and self.cfg.block_quic == "list"
        )
        need_force = self.cfg.quic == "desync" and self.cfg.quic_force_tcp
        if not need_targets and not need_force:
            return

        parts: list[str] = []
        if need_targets:
            parts += [
                f"flush set inet {TABLE} targets4",
                f"flush set inet {TABLE} targets6",
            ]
            if ipv4:
                parts.append(f"add element inet {TABLE} targets4 {{ {', '.join(ipv4)} }}")
            if ipv6:
                parts.append(f"add element inet {TABLE} targets6 {{ {', '.join(ipv6)} }}")
        if need_force:
            parts += [
                f"flush set inet {TABLE} quic_block4",
                f"flush set inet {TABLE} quic_block6",
            ]
            # nftables sets with the interval flag reject overlapping
            # elements, and resolved YouTube addresses almost always fall
            # inside the broad Google ranges.  Merge them first.
            all4 = _merge_networks(QUIC_FORCE_TCP4, force4 or [])
            all6 = _merge_networks(QUIC_FORCE_TCP6, force6 or [])
            if all4:
                parts.append(f"add element inet {TABLE} quic_block4 {{ {', '.join(all4)} }}")
            if all6:
                parts.append(f"add element inet {TABLE} quic_block6 {{ {', '.join(all6)} }}")
        try:
            self._run("\n".join(parts) + "\n")
            log.info(
                "address sets updated: %d IPv4, %d IPv6; force-TCP QUIC %d IPv4, %d IPv6",
                len(ipv4),
                len(ipv6),
                len(force4 or []),
                len(force6 or []),
            )
        except FirewallError as exc:
            log.warning("cannot update address sets: %s", exc)

    def list_table(self) -> str:
        proc = subprocess.run(
            [self.nft, "list", "table", "inet", TABLE], capture_output=True, text=True
        )
        return proc.stdout if proc.returncode == 0 else ""
