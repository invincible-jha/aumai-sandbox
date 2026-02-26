"""aumai-sandbox quickstart example.

Demonstrates:
- Building a CapabilityDeclaration programmatically.
- Parsing a capability from a YAML string.
- Running a command in a sandbox and inspecting the result.
- Validating egress rules and filesystem policies.
- Checking resource limits.

Run this file directly::

    python examples/quickstart.py
"""

from __future__ import annotations

import textwrap

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


def demo_programmatic_sandbox() -> None:
    """Build a capability and execute a command inside a sandbox."""
    print("=" * 60)
    print("Demo 1: Programmatic sandbox execution")
    print("=" * 60)

    capability = CapabilityDeclaration(
        sandbox_tier=SandboxTier.seccomp,
        network_egress_rules=[
            NetworkEgressRule(domain="api.openai.com", ports=[443], rate_limit_per_min=30)
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
    print(f"Created sandbox: {sandbox_id}")
    print(f"Tier: {capability.sandbox_tier.value}")

    result = manager.execute(
        sandbox_id,
        ["python", "-c", "import sys; print('hello from sandbox'); sys.exit(0)"],
        timeout=10.0,
    )
    manager.destroy(sandbox_id)

    print(f"Exit code : {result.exit_code}")
    print(f"Stdout    : {result.stdout.strip()}")
    print(f"Duration  : {result.duration_ms:.0f} ms")
    print(f"CPU secs  : {result.resource_usage.get('cpu_seconds')}")
    print()


def demo_yaml_parsing() -> None:
    """Parse a capability from a YAML string."""
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
    print(f"Tier     : {capability.sandbox_tier.value}")
    print(f"FS mode  : {capability.filesystem_config.mode.value}")
    print(f"Egress   : {len(capability.network_egress_rules)} rules")
    for rule in capability.network_egress_rules:
        print(f"  - {rule.domain}:{rule.ports} @ {rule.rate_limit_per_min}/min")
    print()


def demo_egress_filtering() -> None:
    """Demonstrate network egress filtering."""
    print("=" * 60)
    print("Demo 3: Egress filtering")
    print("=" * 60)

    rules = [
        NetworkEgressRule(domain="*.openai.com", ports=[443]),
        NetworkEgressRule(domain="pypi.org", ports=[443]),
    ]
    egress_filter = EgressFilter(rules)

    test_cases: list[tuple[str, bool]] = [
        ("https://api.openai.com/v1/chat/completions", True),
        ("https://pypi.org/simple/requests/", True),
        ("https://evil.com/exfil?data=secret", False),
        ("https://api.openai.com:80/v1/query", False),  # wrong port
    ]

    for url, expected in test_cases:
        allowed = egress_filter.is_allowed(url)
        status = "ALLOW" if allowed else "DENY "
        marker = "OK" if allowed == expected else "UNEXPECTED"
        print(f"  [{status}] {marker:>10}  {url}")

    # Module-level helper works identically.
    assert check_egress("https://api.openai.com/v1/chat", rules)
    assert not check_egress("https://attacker.io/steal", rules)
    print()


def demo_filesystem_policy() -> None:
    """Demonstrate filesystem path validation."""
    print("=" * 60)
    print("Demo 4: Filesystem policy")
    print("=" * 60)

    config = FilesystemConfig(
        mode=FilesystemMode.read_write,
        writable_paths=["/tmp/agent_work", "/var/agent/output"],
    )
    policy = FilesystemPolicy(config)

    paths: list[tuple[str, str]] = [
        ("/etc/passwd", "read"),
        ("/etc/passwd", "write"),
        ("/tmp/agent_work/results.json", "write"),
        ("/var/agent/output/report.txt", "write"),
        ("/home/user/private_key", "write"),
    ]

    for path, mode in paths:
        allowed = validate_path_access(path, mode, config)
        status = "ALLOW" if allowed else "DENY "
        reason = policy.deny_reason(path, mode)
        note = f"  ({reason})" if reason else ""
        print(f"  [{status}] {mode:5}  {path}{note}")
    print()


def demo_resource_limits() -> None:
    """Demonstrate resource limit checking."""
    print("=" * 60)
    print("Demo 5: Resource limit checking")
    print("=" * 60)

    limits = ResourceLimits(
        max_memory_mb=512,
        max_cpu_seconds=10.0,
        max_cost_usd=0.05,
        max_tokens=5000,
    )

    scenarios: list[dict[str, float | int]] = [
        {"cpu_seconds": 5.0, "peak_memory_mb": 200, "tokens_used": 1000, "cost_usd": 0.01},
        {"cpu_seconds": 15.0, "peak_memory_mb": 200, "tokens_used": 1000, "cost_usd": 0.01},
        {"cpu_seconds": 5.0, "peak_memory_mb": 600, "tokens_used": 1000, "cost_usd": 0.01},
        {"cpu_seconds": 5.0, "peak_memory_mb": 200, "tokens_used": 9999, "cost_usd": 0.01},
        {"cpu_seconds": 5.0, "peak_memory_mb": 200, "tokens_used": 1000, "cost_usd": 0.99},
    ]

    for metrics in scenarios:
        within_limits, reason = check_limits(metrics, limits)
        status = "OK" if within_limits else "VIOLATION"
        print(f"  [{status:>9}]  {reason or 'all limits satisfied'}")
    print()


def main() -> None:
    """Run all quickstart demos."""
    demo_programmatic_sandbox()
    demo_yaml_parsing()
    demo_egress_filtering()
    demo_filesystem_policy()
    demo_resource_limits()
    print("All quickstart demos complete.")


if __name__ == "__main__":
    main()
