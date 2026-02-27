"""Tests for aumai_sandbox.models — Pydantic data models."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from aumai_sandbox.models import (
    CapabilityDeclaration,
    FilesystemConfig,
    FilesystemMode,
    NetworkEgressRule,
    ResourceLimits,
    SandboxResult,
    SandboxStatus,
    SandboxTier,
)

# ---------------------------------------------------------------------------
# SandboxTier
# ---------------------------------------------------------------------------


class TestSandboxTier:
    def test_all_members_are_strings(self) -> None:
        for member in SandboxTier:
            assert isinstance(member.value, str)

    def test_expected_members_exist(self) -> None:
        assert SandboxTier.seccomp.value == "seccomp"
        assert SandboxTier.gvisor.value == "gvisor"
        assert SandboxTier.firecracker.value == "firecracker"

    def test_instantiate_from_string(self) -> None:
        assert SandboxTier("seccomp") is SandboxTier.seccomp
        assert SandboxTier("gvisor") is SandboxTier.gvisor
        assert SandboxTier("firecracker") is SandboxTier.firecracker

    def test_invalid_tier_raises(self) -> None:
        with pytest.raises(ValueError):
            SandboxTier("docker")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# NetworkEgressRule
# ---------------------------------------------------------------------------


class TestNetworkEgressRule:
    def test_valid_rule(self) -> None:
        rule = NetworkEgressRule(domain="api.openai.com", ports=[443])
        assert rule.domain == "api.openai.com"
        assert rule.ports == [443]
        assert rule.rate_limit_per_min == 60  # default

    def test_wildcard_domain(self) -> None:
        rule = NetworkEgressRule(domain="*.openai.com", ports=[443])
        assert rule.domain == "*.openai.com"

    def test_empty_ports_list_is_allowed(self) -> None:
        rule = NetworkEgressRule(domain="trusted.internal", ports=[])
        assert rule.ports == []

    def test_rate_limit_custom(self) -> None:
        rule = NetworkEgressRule(
            domain="api.example.com", ports=[80, 443], rate_limit_per_min=120
        )
        assert rule.rate_limit_per_min == 120

    def test_domain_stripped_of_whitespace(self) -> None:
        rule = NetworkEgressRule(domain="  api.openai.com  ", ports=[443])
        assert rule.domain == "api.openai.com"

    def test_blank_domain_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(domain="   ", ports=[443])

    def test_empty_domain_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(domain="", ports=[443])

    def test_port_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(domain="api.example.com", ports=[0])

    def test_port_too_high_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(domain="api.example.com", ports=[65536])

    def test_port_max_valid(self) -> None:
        rule = NetworkEgressRule(domain="api.example.com", ports=[65535])
        assert 65535 in rule.ports

    def test_port_min_valid(self) -> None:
        rule = NetworkEgressRule(domain="api.example.com", ports=[1])
        assert 1 in rule.ports

    def test_rate_limit_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(
                domain="api.example.com", ports=[443], rate_limit_per_min=0
            )

    def test_negative_port_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(domain="api.example.com", ports=[-1])

    def test_multiple_ports_all_valid(self) -> None:
        rule = NetworkEgressRule(domain="api.example.com", ports=[80, 443, 8080, 8443])
        assert len(rule.ports) == 4

    def test_missing_domain_raises(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEgressRule(ports=[443])  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# FilesystemMode
# ---------------------------------------------------------------------------


class TestFilesystemMode:
    def test_values(self) -> None:
        assert FilesystemMode.read_only.value == "read_only"
        assert FilesystemMode.read_write.value == "read_write"
        assert FilesystemMode.none.value == "none"


# ---------------------------------------------------------------------------
# FilesystemConfig
# ---------------------------------------------------------------------------


class TestFilesystemConfig:
    def test_default_mode_is_read_only(self) -> None:
        config = FilesystemConfig()
        assert config.mode == FilesystemMode.read_only
        assert config.writable_paths == []

    def test_none_mode_no_paths(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.none)
        assert config.mode == FilesystemMode.none

    def test_read_write_with_paths(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent", "/var/output"],
        )
        assert config.mode == FilesystemMode.read_write
        assert "/tmp/agent" in config.writable_paths

    def test_read_write_no_paths_is_valid(self) -> None:
        # read_write with empty writable_paths means "allow all writes"
        config = FilesystemConfig(mode=FilesystemMode.read_write, writable_paths=[])
        assert config.writable_paths == []

    def test_writable_paths_with_read_only_raises(self) -> None:
        with pytest.raises(ValidationError):
            FilesystemConfig(mode=FilesystemMode.read_only, writable_paths=["/tmp"])

    def test_writable_paths_with_none_mode_raises(self) -> None:
        with pytest.raises(ValidationError):
            FilesystemConfig(mode=FilesystemMode.none, writable_paths=["/tmp"])

    def test_invalid_mode_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            FilesystemConfig(mode="execute")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ResourceLimits
# ---------------------------------------------------------------------------


class TestResourceLimits:
    def test_defaults_are_sensible(self) -> None:
        limits = ResourceLimits()
        assert limits.max_memory_mb == 512
        assert limits.max_cpu_seconds == 30.0
        assert limits.max_cost_usd == 0.10
        assert limits.max_tokens == 100_000

    def test_custom_values(self) -> None:
        limits = ResourceLimits(
            max_memory_mb=128,
            max_cpu_seconds=5.0,
            max_cost_usd=0.01,
            max_tokens=1000,
        )
        assert limits.max_memory_mb == 128
        assert limits.max_cpu_seconds == 5.0

    def test_memory_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(max_memory_mb=0)

    def test_negative_memory_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(max_memory_mb=-1)

    def test_cpu_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(max_cpu_seconds=0.0)

    def test_negative_cpu_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(max_cpu_seconds=-1.0)

    def test_cost_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(max_cost_usd=0.0)

    def test_tokens_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceLimits(max_tokens=0)

    def test_tokens_one_is_valid(self) -> None:
        limits = ResourceLimits(max_tokens=1)
        assert limits.max_tokens == 1

    @given(
        memory=st.integers(min_value=1, max_value=1_000_000),
        cpu=st.floats(
            min_value=0.001, max_value=86400.0, allow_nan=False, allow_infinity=False
        ),
        cost=st.floats(
            min_value=0.001, max_value=10_000.0, allow_nan=False, allow_infinity=False
        ),
        tokens=st.integers(min_value=1, max_value=10_000_000),
    )
    @settings(max_examples=50)
    def test_valid_combinations(
        self,
        memory: int,
        cpu: float,
        cost: float,
        tokens: int,
    ) -> None:
        limits = ResourceLimits(
            max_memory_mb=memory,
            max_cpu_seconds=cpu,
            max_cost_usd=cost,
            max_tokens=tokens,
        )
        assert limits.max_memory_mb == memory
        assert limits.max_tokens == tokens


# ---------------------------------------------------------------------------
# CapabilityDeclaration
# ---------------------------------------------------------------------------


class TestCapabilityDeclaration:
    def test_all_defaults(self) -> None:
        cap = CapabilityDeclaration()
        assert cap.sandbox_tier == SandboxTier.seccomp
        assert cap.network_egress_rules == []
        assert cap.filesystem_config.mode == FilesystemMode.read_only
        assert isinstance(cap.resource_limits, ResourceLimits)
        assert cap.permissions == []

    def test_full_construction(self) -> None:
        cap = CapabilityDeclaration(
            sandbox_tier=SandboxTier.gvisor,
            network_egress_rules=[
                NetworkEgressRule(domain="api.openai.com", ports=[443])
            ],
            filesystem_config=FilesystemConfig(mode=FilesystemMode.read_only),
            resource_limits=ResourceLimits(max_memory_mb=256),
            permissions=["read_env", "spawn_subprocess"],
        )
        assert cap.sandbox_tier == SandboxTier.gvisor
        assert len(cap.network_egress_rules) == 1
        assert "read_env" in cap.permissions

    def test_model_dump_round_trip(self) -> None:
        cap = CapabilityDeclaration(
            sandbox_tier=SandboxTier.firecracker,
            permissions=["read_env"],
        )
        dumped = cap.model_dump(mode="json")
        restored = CapabilityDeclaration.model_validate(dumped)
        assert restored.sandbox_tier == cap.sandbox_tier
        assert restored.permissions == cap.permissions

    def test_invalid_tier_raises(self) -> None:
        with pytest.raises(ValidationError):
            CapabilityDeclaration(sandbox_tier="docker")  # type: ignore[arg-type]

    def test_multiple_egress_rules(self) -> None:
        cap = CapabilityDeclaration(
            network_egress_rules=[
                NetworkEgressRule(domain="a.com", ports=[443]),
                NetworkEgressRule(domain="b.com", ports=[80]),
                NetworkEgressRule(domain="c.com", ports=[8080]),
            ]
        )
        assert len(cap.network_egress_rules) == 3


# ---------------------------------------------------------------------------
# SandboxStatus
# ---------------------------------------------------------------------------


class TestSandboxStatus:
    def test_all_values(self) -> None:
        assert SandboxStatus.created.value == "created"
        assert SandboxStatus.running.value == "running"
        assert SandboxStatus.stopped.value == "stopped"
        assert SandboxStatus.failed.value == "failed"

    def test_string_isinstance(self) -> None:
        # SandboxStatus extends str, so comparisons work
        assert SandboxStatus.created == "created"


# ---------------------------------------------------------------------------
# SandboxResult
# ---------------------------------------------------------------------------


class TestSandboxResult:
    def test_minimal_construction(self) -> None:
        result = SandboxResult(exit_code=0, duration_ms=100.0)
        assert result.exit_code == 0
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.resource_usage == {}

    def test_full_construction(self) -> None:
        usage = {
            "cpu_seconds": 1.5, "peak_memory_mb": 50.0,
            "tokens_used": 100, "cost_usd": 0.001,
        }
        result = SandboxResult(
            exit_code=1,
            stdout="hello\n",
            stderr="warning\n",
            duration_ms=500.0,
            resource_usage=usage,
        )
        assert result.exit_code == 1
        assert result.stdout == "hello\n"
        assert result.resource_usage["cpu_seconds"] == 1.5

    def test_negative_duration_raises(self) -> None:
        with pytest.raises(ValidationError):
            SandboxResult(exit_code=0, duration_ms=-1.0)

    def test_zero_duration_is_valid(self) -> None:
        result = SandboxResult(exit_code=0, duration_ms=0.0)
        assert result.duration_ms == 0.0

    def test_missing_exit_code_raises(self) -> None:
        with pytest.raises(ValidationError):
            SandboxResult(duration_ms=100.0)  # type: ignore[call-arg]

    def test_missing_duration_raises(self) -> None:
        with pytest.raises(ValidationError):
            SandboxResult(exit_code=0)  # type: ignore[call-arg]
