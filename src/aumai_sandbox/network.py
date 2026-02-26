"""Network egress filtering for aumai-sandbox."""

from __future__ import annotations

import fnmatch
import urllib.parse

from aumai_sandbox.models import NetworkEgressRule


class EgressFilter:
    """Validate outbound network requests against an allow-list of egress rules.

    All matching is performed in-process; no actual network calls are made.
    A request is allowed only when *at least one* rule matches both the
    domain and the port.  If no rules are configured every request is denied.

    Example::

        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        filt = EgressFilter(rules)
        assert filt.is_allowed("https://api.openai.com/v1/chat/completions")
        assert not filt.is_allowed("https://evil.com/exfil")
    """

    def __init__(self, rules: list[NetworkEgressRule]) -> None:
        self._rules = rules

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_allowed(self, url: str) -> bool:
        """Return True if *url* is permitted by at least one egress rule."""
        return check_egress(url, self._rules)

    def rules_for_domain(self, hostname: str) -> list[NetworkEgressRule]:
        """Return all rules that match *hostname*."""
        return [rule for rule in self._rules if _domain_matches(hostname, rule.domain)]


# ---------------------------------------------------------------------------
# Module-level helper (importable without instantiating EgressFilter)
# ---------------------------------------------------------------------------


def check_egress(url: str, rules: list[NetworkEgressRule]) -> bool:
    """Return True when *url* is permitted by at least one rule in *rules*.

    Args:
        url: The full URL to check, e.g. ``"https://api.example.com/v1/query"``.
        rules: Ordered list of :class:`~aumai_sandbox.models.NetworkEgressRule`
               objects.  An empty list means *deny all*.

    Returns:
        ``True`` if a matching rule exists, ``False`` otherwise.
    """
    parsed = _safe_parse(url)
    if parsed is None:
        return False

    hostname = parsed.hostname or ""
    port = _effective_port(parsed)

    for rule in rules:
        if not _domain_matches(hostname, rule.domain):
            continue
        # Empty ports list means all ports are allowed for this domain.
        if not rule.ports or port in rule.ports:
            return True

    return False


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _safe_parse(url: str) -> urllib.parse.ParseResult | None:
    """Parse *url* and return None if it is malformed."""
    try:
        result = urllib.parse.urlparse(url)
        # urlparse is lenient; require at minimum a hostname.
        if not result.hostname:
            return None
        return result
    except Exception:
        return None


def _effective_port(parsed: urllib.parse.ParseResult) -> int:
    """Return the port number, falling back to the scheme default."""
    if parsed.port is not None:
        return parsed.port
    scheme_defaults: dict[str, int] = {"https": 443, "http": 80, "ftp": 21}
    return scheme_defaults.get(parsed.scheme.lower(), 0)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Return True when *hostname* matches *pattern*.

    *pattern* may use a leading ``*`` wildcard, e.g. ``"*.example.com"``
    matches ``"api.example.com"`` but not ``"example.com"`` itself.
    """
    hostname = hostname.lower()
    pattern = pattern.lower()

    if pattern.startswith("*."):
        # Wildcard: must have at least one label prefix.
        suffix = pattern[2:]  # e.g. "example.com"
        return hostname.endswith("." + suffix) or hostname == suffix
    return fnmatch.fnmatch(hostname, pattern)


__all__ = ["EgressFilter", "check_egress"]
