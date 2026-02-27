"""Pydantic models for aumai-sandbox."""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class SandboxTier(str, enum.Enum):
    """Isolation tier for a sandbox.

    The tiers map to real Linux kernel technologies. On non-Linux hosts the
    SandboxManager falls back to subprocess isolation while preserving all
    capability-declaration semantics.
    """

    seccomp = "seccomp"
    gvisor = "gvisor"
    firecracker = "firecracker"


class NetworkEgressRule(BaseModel):
    """Single allow-listed egress destination."""

    domain: str = Field(
        ..., description="FQDN or wildcard prefix, e.g. '*.example.com'"
    )
    ports: list[int] = Field(
        default_factory=list, description="Allowed TCP/UDP ports; empty = all"
    )
    rate_limit_per_min: int = Field(
        default=60,
        ge=1,
        description="Max outbound requests per minute to this domain",
    )

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, value: str) -> str:
        """Reject blank domain strings."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("domain must not be blank")
        return stripped

    @field_validator("ports")
    @classmethod
    def ports_in_range(cls, values: list[int]) -> list[int]:
        """Validate each port number is in the valid TCP/UDP range."""
        for port in values:
            if not (1 <= port <= 65535):
                raise ValueError(f"port {port} is outside the valid range 1-65535")
        return values


class FilesystemMode(str, enum.Enum):
    """Access level granted to the sandbox filesystem."""

    read_only = "read_only"
    read_write = "read_write"
    none = "none"


class FilesystemConfig(BaseModel):
    """Filesystem isolation policy for a sandbox."""

    mode: FilesystemMode = Field(default=FilesystemMode.read_only)
    writable_paths: list[str] = Field(
        default_factory=list,
        description="Absolute paths writable by the sandbox; only for mode=read_write",
    )

    @model_validator(mode="after")
    def writable_paths_require_read_write(self) -> FilesystemConfig:
        """Ensure writable_paths is only set when mode allows writes."""
        if self.writable_paths and self.mode != FilesystemMode.read_write:
            raise ValueError(
                f"writable_paths must be empty when mode is '{self.mode.value}'; "
                "set mode to 'read_write' to specify writable paths"
            )
        return self


class ResourceLimits(BaseModel):
    """Hard resource caps enforced by the resource monitor."""

    max_memory_mb: int = Field(
        default=512, ge=1, description="Maximum resident memory in MiB"
    )
    max_cpu_seconds: float = Field(
        default=30.0, gt=0.0, description="Maximum total CPU time in seconds"
    )
    max_cost_usd: float = Field(
        default=0.10, gt=0.0, description="Maximum spend in USD (LLM API calls etc.)"
    )
    max_tokens: int = Field(
        default=100_000, ge=1, description="Maximum token budget across all LLM calls"
    )


class CapabilityDeclaration(BaseModel):
    """Full capability specification that governs a sandboxed agent."""

    sandbox_tier: SandboxTier = Field(default=SandboxTier.seccomp)
    network_egress_rules: list[NetworkEgressRule] = Field(default_factory=list)
    filesystem_config: FilesystemConfig = Field(default_factory=FilesystemConfig)
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    permissions: list[str] = Field(
        default_factory=list,
        description="Named capability tokens, e.g. 'read_env', 'spawn_subprocess'",
    )
    env_allowlist: list[str] | None = Field(
        default=None,
        description=(
            "When set and 'read_env' permission is granted, only these specific "
            "environment variable names are passed through to the subprocess "
            "(after sensitive-pattern filtering). None means no additional restriction."
        ),
    )


class SandboxStatus(str, enum.Enum):
    """Lifecycle state of a sandbox instance."""

    created = "created"
    running = "running"
    stopped = "stopped"
    failed = "failed"


class SandboxResult(BaseModel):
    """Outcome of executing a command inside a sandbox."""

    exit_code: int = Field(..., description="Process exit code; 0 = success")
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    duration_ms: float = Field(
        ..., ge=0.0, description="Wall-clock execution time in ms"
    )
    resource_usage: dict[str, Any] = Field(
        default_factory=dict,
        description="Observed metrics: cpu_seconds, peak_memory_mb, tokens_used, cost_usd",  # noqa: E501
    )


__all__ = [
    "CapabilityDeclaration",
    "FilesystemConfig",
    "FilesystemMode",
    "NetworkEgressRule",
    "ResourceLimits",
    "SandboxResult",
    "SandboxStatus",
    "SandboxTier",
]
