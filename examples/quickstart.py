"""aumai-sandbox quickstart example.

Demonstrates:
- Building a CapabilityDeclaration programmatically.
- Parsing a capability from a YAML string.
- Running a command in a sandbox and inspecting the result.
- Validating egress rules and filesystem policies.
- Checking resource limits manually.

Run this file directly::

    python examples/quickstart.py
"""

from __future__ import annotations

import textwrap
import warnings

# Suppress the isolation warning for this demo — in production you should heed it.
warnings.filterwarnings("ignore", category=UserWarning, module="aumai_sandbox")

from aumai_sandbox import (
    CapabilityDeclaration,
    CapabilityParser,
    EgressFilter,
    FilesystemConfig,
    FilesystemMode,
    FilesystemPolicy,
    NetworkEgressRule,
    ResourceLimits,
    SandboxManager,
    SandboxTier,
    check_egress,
    check_limits,
    validate_path_access,
)


# ---------------------------------------------------------------------------
# Demo 1: Programmatic sandbox execution
# ---------------------------------------------------------------------------


def demo_programmatic_sandbox() -> None:
    """Build a CapabilityDeclaration in code, run a command, inspect the result.

    This shows the complete lifecycle: create_sandbox → execute → destroy.
    """
    print("=" * 60)
    print("Demo 1: Programmatic sandbox execution")
    print("=" * 60)

    # Declare exactly what this agent is allowed to do.
    capability = CapabilityDeclaration(
        sandbox_tier=SandboxTier.seccomp,
        network_egress_rules=[
            NetworkEgressRule(
                domain="api.openai.com",
                ports=[443],
                rate_limit_per_min=30,
            )
        ],
        filesystem_config=FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent_work"],
        ),
        resource_limits=ResourceLimits(
            max_memory_mb=128,
            max_cpu_seconds=5.0,
            max_cost_usd=0.01,
            max_tokens=1000,
        ),
        permissions=["read_env"],
    )

    manager = SandboxManager()
    sandbox_id = manager.create_sandbox(capability)
    print(f"  Created sandbox : {sandbox_id}")
    print(f"  Tier            : {capability.sandbox_tier.value}")
    print(f"  Status          : {manager.status(sandbox_id).value}")

    # Run a Python command inside the sandbox.
    result = manager.execute(
        sandbox_id,
        ["python", "-c", "import sys; print('hello from sandbox'); sys.exit(0)"],
        timeout=10.0,
    )
    manager.destroy(sandbox_id)

    print(f"  Exit code  : {result.exit_code}")
    print(f"  Stdout     : {result.stdout.strip()!r}")
    print(f"  Duration   : {result.duration_ms:.0f} ms")
    print(f"  CPU secs   : {result.resource_usage.get('cpu_seconds')}")
    print(f"  Peak mem   : {result.resource_usage.get('peak_memory_mb')} MiB")
    print()


# ---------------------------------------------------------------------------
# Demo 2: YAML capability parsing
# ---------------------------------------------------------------------------


def demo_yaml_parsing() -> None:
    """Parse a capability declaration from a YAML string.

    In production, load from a file: CapabilityParser.from_file("capability.yaml")
    """
    print("=" * 60)
    print("Demo 2: YAML capability parsing")
    print("=" * 60)

    yaml_text = textwrap.dedent(
        """
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

    capability = CapabilityParser.from_string(yaml_text)
    print(f"  Tier       : {capability.sandbox_tier.value}")
    print(f"  FS mode    : {capability.filesystem_config.mode.value}")
    print(f"  Max memory : {capability.resource_limits.max_memory_mb} MiB")
    print(f"  Max CPU    : {capability.resource_limits.max_cpu_seconds} s")
    print(f"  Egress     : {len(capability.network_egress_rules)} rules")
    for rule in capability.network_egress_rules:
        print(f"    - {rule.domain}  ports={rule.ports}  limit={rule.rate_limit_per_min}/min")
    print(f"  Permissions: {capability.permissions}")
    print()


# ---------------------------------------------------------------------------
# Demo 3: Network egress filtering
# ---------------------------------------------------------------------------


def demo_egress_filtering() -> None:
    """Demonstrate in-process network egress validation.

    EgressFilter checks URLs against an allowlist of domain + port rules.
    Domain patterns support leading wildcard: *.example.com
    """
    print("=" * 60)
    print("Demo 3: Network egress filtering")
    print("=" * 60)

    rules = [
        NetworkEgressRule(domain="*.openai.com", ports=[443]),
        NetworkEgressRule(domain="pypi.org", ports=[443]),
    ]
    egress_filter = EgressFilter(rules)

    # (url, expected_result)
    test_cases: list[tuple[str, bool]] = [
        ("https://api.openai.com/v1/chat/completions", True),   # allowed — wildcard match
        ("https://pypi.org/simple/requests/", True),            # allowed — exact match
        ("https://evil.com/exfil?data=secret", False),          # denied — not on allowlist
        ("https://api.openai.com:80/v1/query", False),          # denied — wrong port
        ("https://openai.com/", True),                          # allowed — wildcard covers apex
    ]

    for url, expected in test_cases:
        allowed = egress_filter.is_allowed(url)
        status = "ALLOW" if allowed else "DENY "
        marker = "    " if allowed == expected else "UNEXPECTED"
        print(f"  [{status}] {marker}  {url}")

    # The module-level function works identically — no EgressFilter instance needed.
    assert check_egress("https://api.openai.com/v1/chat", rules)
    assert not check_egress("https://attacker.io/steal", rules)
    print()


# ---------------------------------------------------------------------------
# Demo 4: Filesystem policy validation
# ---------------------------------------------------------------------------


def demo_filesystem_policy() -> None:
    """Demonstrate path-level access control.

    FilesystemPolicy is a logic-layer check. It does not perform OS isolation;
    it is intended as a pre-flight advisory before OS-level controls enforce the
    same rules.
    """
    print("=" * 60)
    print("Demo 4: Filesystem policy")
    print("=" * 60)

    config = FilesystemConfig(
        mode=FilesystemMode.read_write,
        writable_paths=["/tmp/agent_work", "/var/agent/output"],
    )
    policy = FilesystemPolicy(config)

    # (path, mode, expected)
    paths: list[tuple[str, str]] = [
        ("/etc/passwd", "read"),                            # read allowed in read_write mode
        ("/etc/passwd", "write"),                           # write denied — not in writable_paths
        ("/tmp/agent_work/results.json", "write"),          # write allowed — under writable_paths
        ("/var/agent/output/report.txt", "write"),          # write allowed — under writable_paths
        ("/home/user/private_key", "write"),                # write denied — outside writable_paths
    ]

    for path, access_mode in paths:
        allowed = validate_path_access(path, access_mode, config)
        status = "ALLOW" if allowed else "DENY "
        reason = policy.deny_reason(path, access_mode)
        suffix = f"  ({reason})" if reason else ""
        print(f"  [{status}] {access_mode:5}  {path}{suffix}")
    print()


# ---------------------------------------------------------------------------
# Demo 5: Resource limit checking
# ---------------------------------------------------------------------------


def demo_resource_limits() -> None:
    """Demonstrate standalone resource limit evaluation.

    check_limits() can be called independently of the sandbox — useful for
    enforcing limits on LLM usage outside a subprocess context.
    """
    print("=" * 60)
    print("Demo 5: Resource limit checking")
    print("=" * 60)

    limits = ResourceLimits(
        max_memory_mb=512,
        max_cpu_seconds=10.0,
        max_cost_usd=0.05,
        max_tokens=5000,
    )

    scenarios: list[tuple[str, dict[str, float | int]]] = [
        ("all within limits",
         {"cpu_seconds": 5.0, "peak_memory_mb": 200, "tokens_used": 1000, "cost_usd": 0.01}),
        ("cpu exceeded",
         {"cpu_seconds": 15.0, "peak_memory_mb": 200, "tokens_used": 1000, "cost_usd": 0.01}),
        ("memory exceeded",
         {"cpu_seconds": 5.0, "peak_memory_mb": 600, "tokens_used": 1000, "cost_usd": 0.01}),
        ("tokens exceeded",
         {"cpu_seconds": 5.0, "peak_memory_mb": 200, "tokens_used": 9999, "cost_usd": 0.01}),
        ("cost exceeded",
         {"cpu_seconds": 5.0, "peak_memory_mb": 200, "tokens_used": 1000, "cost_usd": 0.99}),
    ]

    for description, metrics in scenarios:
        within_limits, reason = check_limits(metrics, limits)
        status = "OK       " if within_limits else "VIOLATION"
        message = reason or "all limits satisfied"
        print(f"  [{status}]  {description}: {message}")
    print()


# ---------------------------------------------------------------------------
# Demo 6: Multiple commands on the same sandbox
# ---------------------------------------------------------------------------


def demo_reuse_sandbox() -> None:
    """Show that a sandbox can be reused for multiple sequential commands.

    Status transitions: created -> running -> stopped -> running -> stopped ...
    """
    print("=" * 60)
    print("Demo 6: Reusing a sandbox for sequential commands")
    print("=" * 60)

    manager = SandboxManager()
    sandbox_id = manager.create_sandbox(CapabilityDeclaration())

    commands = [
        ["python", "-c", "print('step 1: data loaded')"],
        ["python", "-c", "print('step 2: model called')"],
        ["python", "-c", "print('step 3: result saved')"],
    ]

    for i, cmd in enumerate(commands, start=1):
        result = manager.execute(sandbox_id, cmd, timeout=10.0)
        print(f"  Step {i}: {result.stdout.strip()!r}  exit={result.exit_code}")

    manager.destroy(sandbox_id)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run all quickstart demos in sequence."""
    demo_programmatic_sandbox()
    demo_yaml_parsing()
    demo_egress_filtering()
    demo_filesystem_policy()
    demo_resource_limits()
    demo_reuse_sandbox()
    print("All quickstart demos complete.")


if __name__ == "__main__":
    main()
