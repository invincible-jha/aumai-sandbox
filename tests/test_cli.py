"""Tests for CLI."""

from click.testing import CliRunner

from aumai_sandbox.cli import main


def test_cli_version() -> None:
    """Version flag must report 0.1.0."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
