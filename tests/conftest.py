"""Shared test fixtures for aumai-sandbox test suite."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aumai_sandbox.models import (
    CapabilityDeclaration,
    FilesystemConfig,
    FilesystemMode,
    NetworkEgressRule,
    ResourceLimits,
    SandboxTier,
)

# ---------------------------------------------------------------------------
# ResourceLimits fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_limits() -> ResourceLimits:
    """Return a ResourceLimits with default values."""
    return ResourceLimits()


@pytest.fixture()
def tight_limits() -> ResourceLimits:
    """Return very restrictive ResourceLimits useful for triggering violations."""
    return ResourceLimits(
        max_memory_mb=1,
        max_cpu_seconds=0.001,
        max_cost_usd=0.0001,
        max_tokens=1,
    )


@pytest.fixture()
def generous_limits() -> ResourceLimits:
    """Return generous ResourceLimits that are unlikely to be exceeded in tests."""
    return ResourceLimits(
        max_memory_mb=4096,
        max_cpu_seconds=300.0,
        max_cost_usd=100.0,
        max_tokens=10_000_000,
    )


# ---------------------------------------------------------------------------
# FilesystemConfig fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def read_only_fs_config() -> FilesystemConfig:
    """FilesystemConfig in read_only mode."""
    return FilesystemConfig(mode=FilesystemMode.read_only)


@pytest.fixture()
def read_write_fs_config(tmp_path: Path) -> FilesystemConfig:
    """FilesystemConfig in read_write mode with a real temp directory."""
    return FilesystemConfig(
        mode=FilesystemMode.read_write,
        writable_paths=[str(tmp_path)],
    )


@pytest.fixture()
def no_access_fs_config() -> FilesystemConfig:
    """FilesystemConfig in none (no access) mode."""
    return FilesystemConfig(mode=FilesystemMode.none)


# ---------------------------------------------------------------------------
# NetworkEgressRule fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def openai_egress_rule() -> NetworkEgressRule:
    """Egress rule allowing HTTPS to api.openai.com."""
    return NetworkEgressRule(
        domain="api.openai.com", ports=[443], rate_limit_per_min=30
    )


@pytest.fixture()
def wildcard_openai_rule() -> NetworkEgressRule:
    """Egress rule allowing HTTPS to any *.openai.com subdomain."""
    return NetworkEgressRule(domain="*.openai.com", ports=[443], rate_limit_per_min=60)


@pytest.fixture()
def all_ports_rule() -> NetworkEgressRule:
    """Egress rule with no port restriction (all ports allowed)."""
    return NetworkEgressRule(domain="trusted.internal", ports=[])


# ---------------------------------------------------------------------------
# CapabilityDeclaration fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def minimal_capability() -> CapabilityDeclaration:
    """A CapabilityDeclaration with all default values."""
    return CapabilityDeclaration()


@pytest.fixture()
def full_capability(tmp_path: Path) -> CapabilityDeclaration:
    """A fully populated CapabilityDeclaration."""
    return CapabilityDeclaration(
        sandbox_tier=SandboxTier.seccomp,
        network_egress_rules=[
            NetworkEgressRule(
                domain="api.openai.com", ports=[443], rate_limit_per_min=30
            ),
            NetworkEgressRule(domain="pypi.org", ports=[443]),
        ],
        filesystem_config=FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=[str(tmp_path)],
        ),
        resource_limits=ResourceLimits(
            max_memory_mb=256,
            max_cpu_seconds=10.0,
            max_cost_usd=0.05,
            max_tokens=50_000,
        ),
        permissions=["read_env"],
    )


@pytest.fixture()
def read_env_capability() -> CapabilityDeclaration:
    """Capability with read_env permission for subprocess tests."""
    return CapabilityDeclaration(
        resource_limits=ResourceLimits(
            max_memory_mb=512,
            max_cpu_seconds=30.0,
            max_cost_usd=1.0,
            max_tokens=100_000,
        ),
        permissions=["read_env"],
    )


# ---------------------------------------------------------------------------
# YAML helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_capability_yaml() -> str:
    """A complete valid capability YAML string."""
    return textwrap.dedent(
        """\
        sandbox_tier: gvisor
        resource_limits:
          max_memory_mb: 256
          max_cpu_seconds: 15.0
          max_cost_usd: 0.05
          max_tokens: 50000
        network_egress_rules:
          - domain: "*.openai.com"
            ports: [443]
            rate_limit_per_min: 60
          - domain: "pypi.org"
            ports: [443]
            rate_limit_per_min: 10
        filesystem_config:
          mode: read_only
        permissions:
          - read_env
        """
    )


@pytest.fixture()
def capability_yaml_file(tmp_path: Path, valid_capability_yaml: str) -> Path:
    """Write a valid capability YAML file to a temp directory and return its path."""
    yaml_path = tmp_path / "capability.yaml"
    yaml_path.write_text(valid_capability_yaml, encoding="utf-8")
    return yaml_path
