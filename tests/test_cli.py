"""Tests for aumai_sandbox.cli — CLI entry point."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from aumai_sandbox.cli import main
from aumai_sandbox.core import SandboxError
from aumai_sandbox.models import (
    SandboxResult,
    SandboxStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_capability_file(tmp_path: Path, content: str) -> Path:
    yaml_file = tmp_path / "capability.yaml"
    yaml_file.write_text(content, encoding="utf-8")
    return yaml_file


def _minimal_yaml() -> str:
    return "sandbox_tier: seccomp\n"


def _make_mock_result(
    exit_code: int = 0,
    stdout: str = "hello\n",
    stderr: str = "",
    duration_ms: float = 50.0,
) -> SandboxResult:
    return SandboxResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        resource_usage={
            "cpu_seconds": 0.1,
            "peak_memory_mb": 20.0,
            "tokens_used": 0,
            "cost_usd": 0.0,
        },
    )


# ---------------------------------------------------------------------------
# version flag
# ---------------------------------------------------------------------------


class TestCliVersion:
    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "AumAI Sandbox" in result.output


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------


class TestCliValidate:
    def test_valid_file_text_output(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, _minimal_yaml())
        runner = CliRunner()
        result = runner.invoke(main, ["validate", "--config", str(yaml_file)])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_valid_file_shows_details(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(
            tmp_path,
            textwrap.dedent(
                """\
                sandbox_tier: gvisor
                resource_limits:
                  max_memory_mb: 256
                  max_cpu_seconds: 15.0
                  max_cost_usd: 0.05
                  max_tokens: 50000
                filesystem_config:
                  mode: read_only
                permissions:
                  - read_env
                """
            ),
        )
        runner = CliRunner()
        result = runner.invoke(main, ["validate", "--config", str(yaml_file)])
        assert result.exit_code == 0
        assert "gvisor" in result.output
        assert "read_only" in result.output
        assert "256" in result.output
        assert "read_env" in result.output

    def test_valid_file_json_output(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, _minimal_yaml())
        runner = CliRunner()
        result = runner.invoke(
            main, ["validate", "--config", str(yaml_file), "--output", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["valid"] is True
        assert "capability" in data

    def test_invalid_file_text_output_exits_1(self, tmp_path: Path) -> None:
        bad_yaml = _make_capability_file(tmp_path, "sandbox_tier: unknown_tier\n")
        runner = CliRunner()
        result = runner.invoke(main, ["validate", "--config", str(bad_yaml)])
        assert result.exit_code == 1

    def test_invalid_file_json_output_exits_1(self, tmp_path: Path) -> None:
        bad_yaml = _make_capability_file(tmp_path, "sandbox_tier: unknown_tier\n")
        runner = CliRunner()
        result = runner.invoke(
            main, ["validate", "--config", str(bad_yaml), "--output", "json"]
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["valid"] is False
        assert "error" in data

    def test_nonexistent_config_fails(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["validate", "--config", str(tmp_path / "missing.yaml")]
        )
        # Click itself catches the path error — non-zero exit
        assert result.exit_code != 0

    def test_no_permissions_shows_none(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, "sandbox_tier: seccomp\n")
        runner = CliRunner()
        result = runner.invoke(main, ["validate", "--config", str(yaml_file)])
        assert result.exit_code == 0
        assert "(none)" in result.output


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------


class TestCliRun:
    def test_run_happy_path(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(
            tmp_path,
            textwrap.dedent(
                """\
                sandbox_tier: seccomp
                resource_limits:
                  max_memory_mb: 512
                  max_cpu_seconds: 30.0
                  max_cost_usd: 1.0
                  max_tokens: 100000
                permissions:
                  - read_env
                """
            ),
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "run",
                "--config",
                str(yaml_file),
                "--timeout",
                "20.0",
                "--",
                "python",
                "-c",
                "print('from sandbox')",
            ],
        )
        assert result.exit_code == 0
        assert "from sandbox" in result.output

    def test_run_forwards_exit_code(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(
            tmp_path,
            textwrap.dedent(
                """\
                sandbox_tier: seccomp
                resource_limits:
                  max_cpu_seconds: 30.0
                permissions:
                  - read_env
                """
            ),
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "run",
                "--config",
                str(yaml_file),
                "--",
                "python",
                "-c",
                "import sys; sys.exit(42)",
            ],
        )
        assert result.exit_code == 42

    def test_run_missing_config_exits_nonzero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "run", "--config", "/path/that/does/not/exist.yaml",
                "--", "python", "-c", "pass",
            ],
        )
        assert result.exit_code != 0

    def test_run_missing_command_exits_nonzero(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, _minimal_yaml())
        runner = CliRunner()
        result = runner.invoke(main, ["run", "--config", str(yaml_file)])
        # Click requires at least one command argument
        assert result.exit_code != 0

    def test_run_with_mocked_manager(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, _minimal_yaml())
        mock_result = _make_mock_result(exit_code=0, stdout="mocked output\n")
        mock_mgr = MagicMock()
        mock_mgr.create_sandbox.return_value = "test-sandbox-id"
        mock_mgr.execute.return_value = mock_result

        runner = CliRunner()
        with patch("aumai_sandbox.cli.SandboxManager", return_value=mock_mgr):
            result = runner.invoke(
                main,
                ["run", "--config", str(yaml_file), "--", "python", "-c", "pass"],
            )

        assert "mocked output" in result.output
        mock_mgr.execute.assert_called_once()
        mock_mgr.destroy.assert_called_once_with("test-sandbox-id")

    def test_run_sandbox_error_exits_1(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, _minimal_yaml())
        mock_mgr = MagicMock()
        mock_mgr.create_sandbox.return_value = "test-id"
        mock_mgr.execute.side_effect = SandboxError("execution failed")

        runner = CliRunner()
        with patch("aumai_sandbox.cli.SandboxManager", return_value=mock_mgr):
            result = runner.invoke(
                main,
                ["run", "--config", str(yaml_file), "--", "python", "-c", "pass"],
            )

        assert result.exit_code == 1

    def test_run_shows_resource_summary(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, _minimal_yaml())
        mock_result = _make_mock_result(exit_code=0, stdout="ok\n")
        mock_mgr = MagicMock()
        mock_mgr.create_sandbox.return_value = "test-id"
        mock_mgr.execute.return_value = mock_result

        runner = CliRunner()
        with patch("aumai_sandbox.cli.SandboxManager", return_value=mock_mgr):
            result = runner.invoke(
                main,
                ["run", "--config", str(yaml_file), "--", "python", "-c", "pass"],
            )

        # Resource summary (duration, cpu, mem) is written to stderr but CliRunner
        # mixes it with stdout by default — check the combined output.
        combined = result.output
        assert "finished" in combined

    def test_run_invalid_yaml_exits_1(self, tmp_path: Path) -> None:
        bad_yaml = _make_capability_file(tmp_path, "sandbox_tier: unknown_tier\n")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "--config", str(bad_yaml), "--", "python", "-c", "pass"],
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# inspect command
# ---------------------------------------------------------------------------


class TestCliInspect:
    def test_inspect_known_sandbox(self) -> None:
        from aumai_sandbox.core import SandboxManager as RealManager

        mock_mgr = MagicMock(spec=RealManager)
        mock_mgr.status.return_value = SandboxStatus.running

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inspect", "--sandbox-id", "test-id"],
            obj=mock_mgr,
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["sandbox_id"] == "test-id"
        assert data["status"] == "running"

    def test_inspect_unknown_sandbox_exits_1(self) -> None:
        from aumai_sandbox.core import SandboxManager as RealManager

        mock_mgr = MagicMock(spec=RealManager)
        mock_mgr.status.side_effect = SandboxError("unknown sandbox id: bad-id")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inspect", "--sandbox-id", "bad-id"],
            obj=mock_mgr,
        )

        assert result.exit_code == 1

    def test_inspect_no_obj_uses_fresh_manager(self) -> None:
        """Without ctx.obj, a fresh SandboxManager is used (fails on unknown id)."""
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", "--sandbox-id", "nonexistent-id"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# _load_capability helper
# ---------------------------------------------------------------------------


class TestLoadCapabilityHelper:
    def test_loads_valid_file(self, tmp_path: Path) -> None:
        yaml_file = _make_capability_file(tmp_path, _minimal_yaml())
        runner = CliRunner()
        # _load_capability calls sys.exit(1) on failure; wrap in Click context
        with runner.isolated_filesystem():
            cap = CliRunner().invoke(
                main, ["validate", "--config", str(yaml_file)]
            )
        assert cap.exit_code == 0

    def test_exits_on_parse_error(self, tmp_path: Path) -> None:
        """_load_capability should call sys.exit(1) when parsing fails."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("sandbox_tier: unknown\n", encoding="utf-8")
        runner = CliRunner()
        # The run command calls _load_capability internally
        result = runner.invoke(
            main,
            ["run", "--config", str(bad_file), "--", "python", "-c", "pass"],
        )
        assert result.exit_code == 1
