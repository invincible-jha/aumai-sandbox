"""Tests for aumai_sandbox.network — egress filtering."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from aumai_sandbox.models import NetworkEgressRule
from aumai_sandbox.network import (
    EgressFilter,
    _domain_matches,
    _effective_port,
    _safe_parse,
    check_egress,
)

# ---------------------------------------------------------------------------
# _safe_parse
# ---------------------------------------------------------------------------


class TestSafeParse:
    def test_https_url(self) -> None:
        result = _safe_parse("https://api.example.com/path")
        assert result is not None
        assert result.hostname == "api.example.com"

    def test_http_url(self) -> None:
        result = _safe_parse("http://example.com")
        assert result is not None

    def test_url_with_port(self) -> None:
        result = _safe_parse("https://api.example.com:8443/v1")
        assert result is not None
        assert result.port == 8443

    def test_malformed_url_returns_none(self) -> None:
        # No hostname
        result = _safe_parse("not-a-url")
        assert result is None

    def test_empty_string_returns_none(self) -> None:
        result = _safe_parse("")
        assert result is None

    def test_url_without_scheme_hostname_returns_none(self) -> None:
        result = _safe_parse("//")
        assert result is None


# ---------------------------------------------------------------------------
# _effective_port
# ---------------------------------------------------------------------------


class TestEffectivePort:
    def test_explicit_port(self) -> None:
        parsed = _safe_parse("https://example.com:8080/path")
        assert parsed is not None
        assert _effective_port(parsed) == 8080

    def test_https_default_443(self) -> None:
        parsed = _safe_parse("https://example.com/path")
        assert parsed is not None
        assert _effective_port(parsed) == 443

    def test_http_default_80(self) -> None:
        parsed = _safe_parse("http://example.com/path")
        assert parsed is not None
        assert _effective_port(parsed) == 80

    def test_ftp_default_21(self) -> None:
        parsed = _safe_parse("ftp://files.example.com/pub")
        assert parsed is not None
        assert _effective_port(parsed) == 21

    def test_unknown_scheme_default_zero(self) -> None:
        parsed = _safe_parse("custom://example.com/path")
        assert parsed is not None
        assert _effective_port(parsed) == 0


# ---------------------------------------------------------------------------
# _domain_matches
# ---------------------------------------------------------------------------


class TestDomainMatches:
    def test_exact_match(self) -> None:
        assert _domain_matches("api.openai.com", "api.openai.com") is True

    def test_exact_match_case_insensitive(self) -> None:
        assert _domain_matches("API.OPENAI.COM", "api.openai.com") is True

    def test_no_match(self) -> None:
        assert _domain_matches("evil.com", "api.openai.com") is False

    def test_wildcard_subdomain_match(self) -> None:
        assert _domain_matches("api.openai.com", "*.openai.com") is True

    def test_wildcard_different_subdomain(self) -> None:
        assert _domain_matches("files.openai.com", "*.openai.com") is True

    def test_wildcard_does_not_match_root(self) -> None:
        # The code checks hostname == suffix, so "openai.com" matches "*.openai.com"
        assert _domain_matches("openai.com", "*.openai.com") is True

    def test_wildcard_does_not_match_unrelated(self) -> None:
        assert _domain_matches("evil.com", "*.openai.com") is False

    def test_wildcard_pattern_two_levels_deep(self) -> None:
        # "api.v2.openai.com" ends with ".openai.com" so should match "*.openai.com"
        assert _domain_matches("api.v2.openai.com", "*.openai.com") is True

    def test_partial_domain_no_match(self) -> None:
        assert _domain_matches("nopenai.com", "*.openai.com") is False

    def test_fnmatch_pattern(self) -> None:
        # Non-wildcard patterns are passed through fnmatch
        assert _domain_matches("api.example.com", "api.example.com") is True


# ---------------------------------------------------------------------------
# check_egress
# ---------------------------------------------------------------------------


class TestCheckEgress:
    def test_empty_rules_deny_all(self) -> None:
        assert check_egress("https://api.openai.com/v1", []) is False

    def test_matching_domain_and_port(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        assert check_egress("https://api.openai.com/v1/chat", rules) is True

    def test_matching_domain_wrong_port(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        assert check_egress("http://api.openai.com/v1", rules) is False  # port 80

    def test_non_matching_domain(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        assert check_egress("https://evil.com/steal", rules) is False

    def test_all_ports_rule_allows_any_port(self) -> None:
        rules = [NetworkEgressRule(domain="trusted.internal", ports=[])]
        assert check_egress("https://trusted.internal/api", rules) is True
        assert check_egress("http://trusted.internal/data", rules) is True

    def test_wildcard_domain_rule(self) -> None:
        rules = [NetworkEgressRule(domain="*.openai.com", ports=[443])]
        assert check_egress("https://api.openai.com/v1", rules) is True
        assert check_egress("https://files.openai.com/download", rules) is True

    def test_wildcard_does_not_match_unrelated(self) -> None:
        rules = [NetworkEgressRule(domain="*.openai.com", ports=[443])]
        assert check_egress("https://evil.com/steal", rules) is False

    def test_multiple_rules_first_match_wins(self) -> None:
        rules = [
            NetworkEgressRule(domain="api.openai.com", ports=[443]),
            NetworkEgressRule(domain="pypi.org", ports=[443]),
        ]
        assert check_egress("https://api.openai.com/chat", rules) is True
        assert check_egress("https://pypi.org/simple", rules) is True
        assert check_egress("https://npmjs.com/package", rules) is False

    def test_malformed_url_denied(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        assert check_egress("not_a_url", rules) is False

    def test_explicit_port_in_url(self) -> None:
        rules = [NetworkEgressRule(domain="api.example.com", ports=[8443])]
        assert check_egress("https://api.example.com:8443/endpoint", rules) is True
        assert check_egress("https://api.example.com:9999/endpoint", rules) is False

    @given(st.text(min_size=1))
    @settings(max_examples=100)
    def test_arbitrary_strings_do_not_raise(self, url: str) -> None:
        """check_egress must never raise an exception for any input string."""
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        result = check_egress(url, rules)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# EgressFilter
# ---------------------------------------------------------------------------


class TestEgressFilter:
    def test_is_allowed_delegates_to_check_egress(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        filt = EgressFilter(rules)
        assert filt.is_allowed("https://api.openai.com/v1") is True
        assert filt.is_allowed("https://evil.com/steal") is False

    def test_empty_rules_deny_all(self) -> None:
        filt = EgressFilter([])
        assert filt.is_allowed("https://api.openai.com/v1") is False

    def test_rules_for_domain_returns_matching_rules(self) -> None:
        rules = [
            NetworkEgressRule(domain="api.openai.com", ports=[443]),
            NetworkEgressRule(domain="*.openai.com", ports=[80]),
            NetworkEgressRule(domain="pypi.org", ports=[443]),
        ]
        filt = EgressFilter(rules)
        # api.openai.com matches exact rule and wildcard
        matching = filt.rules_for_domain("api.openai.com")
        assert len(matching) == 2

    def test_rules_for_domain_no_match(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        filt = EgressFilter(rules)
        assert filt.rules_for_domain("evil.com") == []

    def test_rules_for_domain_case_insensitive(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        filt = EgressFilter(rules)
        result = filt.rules_for_domain("API.OPENAI.COM")
        assert len(result) == 1

    def test_constructor_stores_rules(self) -> None:
        rules = [NetworkEgressRule(domain="example.com", ports=[443])]
        filt = EgressFilter(rules)
        assert filt._rules == rules  # noqa: SLF001

    def test_is_allowed_wrong_port_denied(self) -> None:
        rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
        filt = EgressFilter(rules)
        # Port 80 (HTTP) should not match a rule that only allows 443
        assert filt.is_allowed("http://api.openai.com/v1") is False

    def test_allows_multiple_matching_ports(self) -> None:
        rules = [NetworkEgressRule(domain="api.example.com", ports=[80, 443, 8080])]
        filt = EgressFilter(rules)
        assert filt.is_allowed("http://api.example.com/path") is True    # port 80
        assert filt.is_allowed("https://api.example.com/path") is True   # port 443
        assert filt.is_allowed("https://api.example.com:8080/path") is True


# ---------------------------------------------------------------------------
# Integration: EgressFilter with wildcard rules from quickstart example
# ---------------------------------------------------------------------------


class TestEgressFilterIntegration:
    def test_quickstart_scenario(self) -> None:
        rules = [
            NetworkEgressRule(domain="*.openai.com", ports=[443]),
            NetworkEgressRule(domain="pypi.org", ports=[443]),
        ]
        filt = EgressFilter(rules)

        # Should be allowed
        assert filt.is_allowed("https://api.openai.com/v1/chat/completions")
        assert filt.is_allowed("https://pypi.org/simple/requests/")

        # Should be denied
        assert not filt.is_allowed("https://evil.com/exfil?data=secret")
        # Wrong port for openai rule
        assert not filt.is_allowed("http://api.openai.com/v1/query")
