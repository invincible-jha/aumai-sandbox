"""AumAI Sandbox — secure execution environment for AI agents.

Public API::

    from aumai_sandbox import (
        CapabilityDeclaration,
        CapabilityParser,
        FilesystemConfig,
        FilesystemMode,
        NetworkEgressRule,
        ResourceLimits,
        SandboxManager,
        SandboxResult,
        SandboxStatus,
        SandboxTier,
        check_egress,
        check_limits,
        validate_path_access,
    )
"""

from aumai_sandbox.core import CapabilityParseError, CapabilityParser, SandboxError, SandboxManager
from aumai_sandbox.filesystem import FilesystemPolicy, validate_path_access
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
from aumai_sandbox.network import EgressFilter, check_egress
from aumai_sandbox.resources import ResourceMonitor, check_limits

__version__ = "0.1.0"

__all__ = [
    # models
    "CapabilityDeclaration",
    "FilesystemConfig",
    "FilesystemMode",
    "NetworkEgressRule",
    "ResourceLimits",
    "SandboxResult",
    "SandboxStatus",
    "SandboxTier",
    # core
    "CapabilityParseError",
    "CapabilityParser",
    "SandboxError",
    "SandboxManager",
    # network
    "EgressFilter",
    "check_egress",
    # filesystem
    "FilesystemPolicy",
    "validate_path_access",
    # resources
    "ResourceMonitor",
    "check_limits",
]
