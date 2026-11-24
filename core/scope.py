from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse


class ScopeViolation(ValueError):
    pass


class Scope:
    def __init__(
        self,
        target: str,
        allowed_hosts: set[str],
        allow_private_targets: bool = False,
        allowed_ports: set[int] | None = None,
    ) -> None:
        parsed = urlparse(target)
        self.target = target
        self.allow_private_targets = allow_private_targets
        self.target_host = self.normalize_host(parsed.hostname or "")
        self.allowed_hosts = {self.normalize_host(host) for host in allowed_hosts if host}
        self.allowed_hosts.add(self.target_host)
        self.allowed_ports = allowed_ports or {80 if parsed.scheme == "http" else 443}
        self.allowed_ports.add(parsed.port or (80 if parsed.scheme == "http" else 443))

    @classmethod
    def from_target(
        cls,
        target: str,
        extra_hosts: list[str],
        allow_private_targets: bool = False,
    ) -> "Scope":
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Target must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are not allowed")
        return cls(target, set(extra_hosts), allow_private_targets)

    @staticmethod
    def normalize_host(host: str) -> str:
        host = host.strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeViolation("Invalid hostname") from exc

    def validate_url(self, url: str, base: str | None = None) -> str:
        absolute = urljoin(base or self.target, url)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolation("Only HTTP and HTTPS URLs are allowed")
        if parsed.username or parsed.password:
            raise ScopeViolation("URLs containing credentials are not allowed")
        if not parsed.hostname:
            raise ScopeViolation("URL has no valid hostname")
        host = self.normalize_host(parsed.hostname)
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        if port not in self.allowed_ports:
            raise ScopeViolation(f"Port {port} is outside the authorized scope")
        if not self._host_allowed(host):
            raise ScopeViolation(f"Hostname '{host}' is outside the authorized scope")
        self._validate_dns(host)
        return parsed._replace(fragment="", netloc=self._netloc(parsed, host, port)).geturl()

    def _netloc(self, parsed, host: str, port: int) -> str:
        default_port = 80 if parsed.scheme == "http" else 443
        if port == default_port:
            return host
        return f"{host}:{port}"

    def _host_allowed(self, host: str) -> bool:
        if host == self.target_host:
            return True
        for allowed in self.allowed_hosts:
            if host == allowed:
                return True
            if host.endswith("." + allowed):
                return True
        return False

    def _validate_dns(self, host: str) -> None:
        try:
            addresses = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise ScopeViolation(f"Could not resolve '{host}'") from exc
        resolved = set()
        for family, _, _, _, sockaddr in addresses:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = sockaddr[0].split("%", 1)[0]
            resolved.add(address)
        if not resolved:
            raise ScopeViolation(f"No usable addresses resolved for '{host}'")
        for address in resolved:
            try:
                parsed_ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ScopeViolation(f"Invalid resolved address for '{host}'") from exc
            if not self.allow_private_targets and (
                parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local
                or parsed_ip.is_reserved or parsed_ip.is_multicast
                or parsed_ip.is_unspecified
                or parsed_ip in ipaddress.ip_network("100.64.0.0/10")
            ):
                raise ScopeViolation(
                    f"Resolved address '{address}' for '{host}' is not a public address"
                )

    def contains(self, url: str) -> bool:
        try:
            self.validate_url(url)
            return True
        except (ScopeViolation, ValueError):
            return False
