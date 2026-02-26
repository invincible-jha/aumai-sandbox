"""CLI entry point for aumai-sandbox."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from aumai_sandbox.core import CapabilityParseError, CapabilityParser, SandboxError, SandboxManager
from aumai_sandbox.models import CapabilityDeclaration


@click.group()
@click.version_option(package_name="aumai-sandbox")
def main() -> None:
    """AumAI Sandbox — secure execution environment for AI agents.

    Run untrusted agents with declared capability bounds and enforced resource
    limits.  Use 'aumai-sandbox --help' to see available sub-commands.
    """


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@main.command("run")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to capability YAML file.",
)
@click.option(
    "--timeout",
    default=60.0,
    show_default=True,
    type=float,
    help="Wall-clock execution timeout in seconds.",
)
@click.argument("command", nargs=-1, required=True)
def run_command(config_path: str, timeout: float, command: tuple[str, ...]) -> None:
    """Run an agent command inside a sandbox.

    \b
    Example:
        aumai-sandbox run --config capability.yaml -- python agent.py --verbose
    """
    capability = _load_capability(config_path)
    manager = SandboxManager()
    sandbox_id = manager.create_sandbox(capability)

    click.echo(
        click.style(f"[sandbox] created  id={sandbox_id}  tier={capability.sandbox_tier.value}",
                    fg="cyan")
    )
    click.echo(click.style(f"[sandbox] running  $ {' '.join(command)}", fg="cyan"))

    try:
        result = manager.execute(sandbox_id, list(command), timeout=timeout)
    except SandboxError as exc:
        click.echo(click.style(f"[sandbox] error: {exc}", fg="red"), err=True)
        sys.exit(1)
    finally:
        try:
            manager.destroy(sandbox_id)
        except SandboxError:
            pass

    # Surface stdout / stderr transparently.
    if result.stdout:
        click.echo(result.stdout, nl=False)
    if result.stderr:
        click.echo(result.stderr, nl=False, err=True)

    # Print resource summary.
    usage = result.resource_usage
    click.echo(
        click.style(
            f"\n[sandbox] finished  exit={result.exit_code}  "
            f"duration={result.duration_ms:.0f}ms  "
            f"cpu={usage.get('cpu_seconds', '?')}s  "
            f"mem={usage.get('peak_memory_mb', '?')}MiB",
            fg="green" if result.exit_code == 0 else "red",
        ),
        err=True,
    )

    sys.exit(result.exit_code)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@main.command("validate")
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(file_okay=True, dir_okay=False, readable=True),
    help="Path to capability YAML file.",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format.",
)
def validate_command(config_path: str, output_format: str) -> None:
    """Validate a capability YAML file without running anything.

    Exits with code 0 when the file is valid, 1 when validation fails.
    """
    try:
        capability = CapabilityParser.from_file(config_path)
    except CapabilityParseError as exc:
        if output_format == "json":
            click.echo(json.dumps({"valid": False, "error": str(exc)}))
        else:
            click.echo(click.style(f"INVALID: {exc}", fg="red"), err=True)
        sys.exit(1)

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "valid": True,
                    "capability": capability.model_dump(mode="json"),
                },
                indent=2,
            )
        )
    else:
        click.echo(click.style("VALID", fg="green"))
        click.echo(f"  sandbox_tier       : {capability.sandbox_tier.value}")
        click.echo(f"  filesystem_mode    : {capability.filesystem_config.mode.value}")
        click.echo(f"  max_memory_mb      : {capability.resource_limits.max_memory_mb}")
        click.echo(f"  max_cpu_seconds    : {capability.resource_limits.max_cpu_seconds}")
        click.echo(f"  max_cost_usd       : {capability.resource_limits.max_cost_usd}")
        click.echo(f"  max_tokens         : {capability.resource_limits.max_tokens}")
        click.echo(f"  egress_rules       : {len(capability.network_egress_rules)}")
        click.echo(f"  permissions        : {', '.join(capability.permissions) or '(none)'}")


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


@main.command("inspect")
@click.option(
    "--sandbox-id",
    "sandbox_id",
    required=True,
    help="Sandbox ID to inspect (returned by 'run').",
)
@click.pass_context
def inspect_command(ctx: click.Context, sandbox_id: str) -> None:
    """Show status information for an active sandbox.

    Note: sandboxes are in-process objects; this command is most useful when
    called programmatically via the Python API.  From the CLI the sandbox will
    have already exited by the time this command runs.
    """
    # The manager is ephemeral per-process; expose a contextual one if passed.
    manager: SandboxManager = ctx.obj if isinstance(ctx.obj, SandboxManager) else SandboxManager()

    try:
        sandbox_status = manager.status(sandbox_id)
    except SandboxError as exc:
        click.echo(click.style(f"error: {exc}", fg="red"), err=True)
        sys.exit(1)

    click.echo(
        json.dumps(
            {"sandbox_id": sandbox_id, "status": sandbox_status.value},
            indent=2,
        )
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _load_capability(config_path: str) -> CapabilityDeclaration:
    """Load a CapabilityDeclaration from a YAML file, printing errors and exiting on failure."""
    try:
        return CapabilityParser.from_file(Path(config_path))
    except CapabilityParseError as exc:
        click.echo(click.style(f"capability error: {exc}", fg="red"), err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
