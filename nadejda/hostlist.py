"""Hostlist matching and address-set resolution."""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# Suffixes that must never be touched even if they appear in the list.
NEVER = (
    "localhost",
    "local",
    "lan",
    "internal",
    "home.arpa",
)


class HostList:
    def __init__(self, domains: list[str]):
        self.domains = sorted({d.strip().lower().lstrip(".") for d in domains if d.strip()})
        self._exact = set(self.domains)
        self._suffixes = tuple("." + d for d in self.domains)

    def matches(self, host: str | None) -> bool:
        if not host:
            return False
        host = host.strip().lower().rstrip(".")
        if host in self._exact:
            return True
        return host.endswith(self._suffixes)

    def __len__(self) -> int:
        return len(self.domains)

    def resolve(self, resolver) -> tuple[list[str], list[str]]:
        return resolver.resolve_many(self.domains)
