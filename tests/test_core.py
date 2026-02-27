"""Tests for aumai_sandbox.core — CapabilityParser and SandboxManager."""

from __future__ import annotations

import textwrap
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

from aumai_sandbox.core import (
    CapabilityParseError,
    CapabilityParser,
    SandboxError,
    SandboxManager,
    _SandboxState,
    _SENSITIVE_ENV_PATTERNS,
    _filter_environment,
)
from aumai_sandbox.models import (
    CapabilityDeclaration,
    FilesystemMode,
    ResourceLimits,
    SandboxStatus,
    SandboxTier,
)

# ---------------------------------------------------------------------------
# CapabilityParser.from_string
# ---------------------------------------------------------------------------


class TestCapabilityParserFromString:
    def test_empty_yaml_uses_defaults(self) -> None:
        cap = CapabilityParser.from_string("")
        assert cap.sandbox_tier == SandboxTier.seccomp
        assert cap.network_egress_rules == []

    def test_null_yaml_uses_defaults(self) -> None:
        cap = CapabilityParser.from_string("~")
        assert isinstance(cap, CapabilityDeclaration)

    def test_full_valid_yaml(self, valid_capability_yaml: str) -> None:
        cap = CapabilityParser.from_string(valid_capability_yaml)
        assert cap.sandbox_tier == SandboxTier.gvisor
        assert cap.resource_limits.max_memory_mb == 256
        assert cap.resource_limits.max_cpu_seconds == 15.0
        assert cap.resource_limits.max_cost_usd == 0.05
        assert cap.resource_limits.max_tokens == 50_000
        assert len(cap.network_egress_rules) == 2
        assert cap.filesystem_config.mode == FilesystemMode.read_only
        assert "read_env" in cap.permissions

    def test_minimal_yaml_with_tier_only(self) -> None:
        cap = CapabilityParser.from_string("sandbox_tier: firecracker\n")
        assert cap.sandbox_tier == SandboxTier.firecracker

    def test_malformed_yaml_raises(self) -> None:
        with pytest.raises(CapabilityParseError, match="YAML parse error"):
            CapabilityParser.from_string("{ invalid yaml: [")

    def test_non_mapping_yaml_raises(self) -> None:
        with pytest.raises(CapabilityParseError, match="must be a YAML mapping"):
            CapabilityParser.from_string("- item1\n- item2\n")

    def test_scalar_yaml_raises(self) -> None:
        with pytest.raises(CapabilityParseError, match="must be a YAML mapping"):
            CapabilityParser.from_string("just_a_string")

    def test_invalid_field_value_raises(self) -> None:
        with pytest.raises(CapabilityParseError, match="capability validation error"):
            CapabilityParser.from_string("sandbox_tier: nonexistent_tier\n")

    def test_egress_rule_with_invalid_port_raises(self) -> None:
        yaml_text = textwrap.dedent(
            """\
            network_egress_rules:
              - domain: "api.example.com"
                ports: [0]
            """
        )
        with pytest.raises(CapabilityParseError):
            CapabilityParser.from_string(yaml_text)

    def test_writable_paths_wrong_mode_raises(self) -> None:
        yaml_text = textwrap.dedent(
            """\
            filesystem_config:
              mode: read_only
              writable_paths: ["/tmp"]
            """
        )
        with pytest.raises(CapabilityParseError):
            CapabilityParser.from_string(yaml_text)

    def test_resource_limits_partial_override(self) -> None:
        yaml_text = "resource_limits:\n  max_memory_mb: 128\n"
        cap = CapabilityParser.from_string(yaml_text)
        assert cap.resource_limits.max_memory_mb == 128
        # Other limits use their defaults
        assert cap.resource_limits.max_cpu_seconds == 30.0

    def test_permissions_list_parsed(self) -> None:
        yaml_text = "permissions:\n  - read_env\n  - spawn_subprocess\n"
        cap = CapabilityParser.from_string(yaml_text)
        assert "read_env" in cap.permissions
        assert "spawn_subprocess" in cap.permissions


# ---------------------------------------------------------------------------
# CapabilityParser.from_file
# ---------------------------------------------------------------------------


class TestCapabilityParserFromFile:
    def test_valid_file(self, capability_yaml_file: Path) -> None:
        cap = CapabilityParser.from_file(capability_yaml_file)
        assert cap.sandbox_tier == SandboxTier.gvisor

    def test_string_path_accepted(self, capability_yaml_file: Path) -> None:
        cap = CapabilityParser.from_file(str(capability_yaml_file))
        assert isinstance(cap, CapabilityDeclaration)

    def test_nonexistent_file_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist.yaml"
        with pytest.raises(CapabilityParseError, match="capability file not found"):
            CapabilityParser.from_file(missing)

    def test_directory_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(CapabilityParseError, match="path is not a file"):
            CapabilityParser.from_file(tmp_path)

    def test_unreadable_file_raises(self, tmp_path: Path) -> None:
        """Simulate an OSError when reading the file."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("sandbox_tier: seccomp\n", encoding="utf-8")
        with patch.object(Path, "read_text", side_effect=OSError("permission denied")):
            with pytest.raises(
                CapabilityParseError, match="cannot read capability file"
            ):
                CapabilityParser.from_file(bad_file)

    def test_file_with_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("{ invalid: [", encoding="utf-8")
        with pytest.raises(CapabilityParseError, match="YAML parse error"):
            CapabilityParser.from_file(bad_yaml)

    def test_file_with_invalid_model_raises(self, tmp_path: Path) -> None:
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("sandbox_tier: unknown_tier\n", encoding="utf-8")
        with pytest.raises(CapabilityParseError, match="capability validation error"):
            CapabilityParser.from_file(bad_yaml)


# ---------------------------------------------------------------------------
# _SandboxState internal class
# ---------------------------------------------------------------------------


class TestSandboxState:
    def test_initial_status_is_created(self) -> None:
        cap = CapabilityDeclaration()
        state = _SandboxState(sandbox_id="test-id", capability=cap)
        assert state.status == SandboxStatus.created

    def test_initial_process_is_none(self) -> None:
        cap = CapabilityDeclaration()
        state = _SandboxState(sandbox_id="test-id", capability=cap)
        assert state.process is None

    def test_initial_monitor_is_none(self) -> None:
        cap = CapabilityDeclaration()
        state = _SandboxState(sandbox_id="test-id", capability=cap)
        assert state.monitor is None


# ---------------------------------------------------------------------------
# SandboxManager — lifecycle
# ---------------------------------------------------------------------------


class TestSandboxManagerLifecycle:
    def test_create_returns_uuid_string(
        self, minimal_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(minimal_capability)
        assert isinstance(sandbox_id, str)
        assert len(sandbox_id) == 36  # UUID format

    def test_create_multiple_sandboxes_unique_ids(
        self, minimal_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        ids = {mgr.create_sandbox(minimal_capability) for _ in range(10)}
        assert len(ids) == 10  # All unique

    def test_status_after_creation(
        self, minimal_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(minimal_capability)
        assert mgr.status(sandbox_id) == SandboxStatus.created

    def test_status_unknown_id_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="unknown sandbox id"):
            mgr.status("nonexistent-id")

    def test_destroy_removes_sandbox(
        self, minimal_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(minimal_capability)
        mgr.destroy(sandbox_id)
        with pytest.raises(SandboxError):
            mgr.status(sandbox_id)

    def test_destroy_unknown_id_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError):
            mgr.destroy("nonexistent-id")

    def test_list_sandboxes_empty_initially(self) -> None:
        mgr = SandboxManager()
        assert mgr.list_sandboxes() == []

    def test_list_sandboxes_returns_created(
        self, minimal_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(minimal_capability)
        sandboxes = mgr.list_sandboxes()
        assert len(sandboxes) == 1
        assert sandboxes[0]["sandbox_id"] == sandbox_id
        assert sandboxes[0]["status"] == "created"
        assert sandboxes[0]["tier"] == "seccomp"

    def test_list_sandboxes_removed_after_destroy(
        self, minimal_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(minimal_capability)
        mgr.destroy(sandbox_id)
        assert mgr.list_sandboxes() == []

    def test_list_sandboxes_multiple(
        self, minimal_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        mgr.create_sandbox(minimal_capability)
        mgr.create_sandbox(minimal_capability)
        mgr.create_sandbox(minimal_capability)
        assert len(mgr.list_sandboxes()) == 3


# ---------------------------------------------------------------------------
# SandboxManager — execute (happy paths)
# ---------------------------------------------------------------------------


class TestSandboxManagerExecute:
    def test_execute_echo_command(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        result = mgr.execute(
            sandbox_id, ["python", "-c", "print('hello sandbox')"], timeout=15.0
        )
        mgr.destroy(sandbox_id)

        assert result.exit_code == 0
        assert "hello sandbox" in result.stdout
        assert result.duration_ms >= 0.0

    def test_execute_exit_code_1(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        result = mgr.execute(
            sandbox_id,
            ["python", "-c", "import sys; sys.exit(1)"],
            timeout=15.0,
        )
        mgr.destroy(sandbox_id)
        assert result.exit_code == 1

    def test_execute_stderr_captured(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        result = mgr.execute(
            sandbox_id,
            ["python", "-c", "import sys; sys.stderr.write('err output\\n')"],
            timeout=15.0,
        )
        mgr.destroy(sandbox_id)
        assert "err output" in result.stderr

    def test_execute_result_has_resource_usage(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        result = mgr.execute(sandbox_id, ["python", "-c", "pass"], timeout=15.0)
        mgr.destroy(sandbox_id)
        assert "cpu_seconds" in result.resource_usage
        assert "peak_memory_mb" in result.resource_usage
        assert "tokens_used" in result.resource_usage
        assert "cost_usd" in result.resource_usage

    def test_execute_after_stop_is_allowed(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        """A stopped sandbox should be re-executable."""
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)

        r1 = mgr.execute(sandbox_id, ["python", "-c", "print('first')"], timeout=15.0)
        assert r1.exit_code == 0
        assert mgr.status(sandbox_id) == SandboxStatus.stopped

        r2 = mgr.execute(sandbox_id, ["python", "-c", "print('second')"], timeout=15.0)
        assert r2.exit_code == 0

        mgr.destroy(sandbox_id)

    def test_execute_unknown_id_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="unknown sandbox id"):
            mgr.execute("nonexistent-id", ["python", "-c", "pass"])

    def test_execute_sets_status_to_stopped_on_success(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        mgr.execute(sandbox_id, ["python", "-c", "pass"], timeout=15.0)
        assert mgr.status(sandbox_id) == SandboxStatus.stopped

    def test_execute_invalid_command_returns_nonzero(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        """A command that doesn't exist should fail gracefully."""
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        result = mgr.execute(
            sandbox_id,
            ["python", "-c", "this_is_not_valid_python_syntax !!!"],
            timeout=15.0,
        )
        mgr.destroy(sandbox_id)
        # Syntax error → non-zero exit code
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# SandboxManager — execute (error paths)
# ---------------------------------------------------------------------------


class TestSandboxManagerExecuteErrors:
    def test_execute_nonexistent_binary_returns_error_result(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        """Running a nonexistent binary should return an error SandboxResult."""
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        result = mgr.execute(
            sandbox_id,
            ["this_binary_does_not_exist_at_all_12345"],
            timeout=15.0,
        )
        mgr.destroy(sandbox_id)
        # Should return -1 exit code with error in stderr
        assert result.exit_code == -1
        assert "sandbox execution error" in result.stderr


# ---------------------------------------------------------------------------
# SandboxManager — _build_environment
# ---------------------------------------------------------------------------


class TestBuildEnvironment:
    def test_without_read_env_restricts_vars(self) -> None:
        cap = CapabilityDeclaration(permissions=[])
        mgr = SandboxManager()
        env = mgr._build_environment(cap)  # noqa: SLF001
        # Only safe keys should be present (or a subset)
        safe_keys = {"PATH", "PYTHONPATH", "SYSTEMROOT", "TEMP", "TMP", "HOME"}
        for key in env:
            assert key in safe_keys

    def test_with_read_env_includes_full_env(self) -> None:
        import os

        cap = CapabilityDeclaration(permissions=["read_env"])
        mgr = SandboxManager()
        env = mgr._build_environment(cap)  # noqa: SLF001
        # Should be a superset of the restricted environment
        assert len(env) >= len(
            {k: v for k, v in os.environ.items() if k in {"PATH", "PYTHONPATH"}}
        )


# ---------------------------------------------------------------------------
# SandboxManager — _build_command_prefix
# ---------------------------------------------------------------------------


class TestBuildCommandPrefix:
    def test_non_linux_returns_empty_prefix(self) -> None:
        cap = CapabilityDeclaration(sandbox_tier=SandboxTier.gvisor)
        mgr = SandboxManager()
        with patch("platform.system", return_value="Windows"):
            prefix = mgr._build_command_prefix(cap)  # noqa: SLF001
        assert prefix == []

    def test_linux_seccomp_returns_empty_prefix(self) -> None:
        cap = CapabilityDeclaration(sandbox_tier=SandboxTier.seccomp)
        mgr = SandboxManager()
        with patch("platform.system", return_value="Linux"):
            prefix = mgr._build_command_prefix(cap)  # noqa: SLF001
        assert prefix == []

    def test_linux_gvisor_returns_runsc(self) -> None:
        cap = CapabilityDeclaration(sandbox_tier=SandboxTier.gvisor)
        mgr = SandboxManager()
        with patch("platform.system", return_value="Linux"):
            prefix = mgr._build_command_prefix(cap)  # noqa: SLF001
        assert prefix == ["runsc", "run"]

    def test_linux_firecracker_returns_empty_prefix(self) -> None:
        cap = CapabilityDeclaration(sandbox_tier=SandboxTier.firecracker)
        mgr = SandboxManager()
        with patch("platform.system", return_value="Linux"):
            prefix = mgr._build_command_prefix(cap)  # noqa: SLF001
        assert prefix == []

    def test_macos_returns_empty_prefix(self) -> None:
        cap = CapabilityDeclaration(sandbox_tier=SandboxTier.gvisor)
        mgr = SandboxManager()
        with patch("platform.system", return_value="Darwin"):
            prefix = mgr._build_command_prefix(cap)  # noqa: SLF001
        assert prefix == []


# ---------------------------------------------------------------------------
# S-C1: Isolation warning tests
# ---------------------------------------------------------------------------


class TestIsolationWarning:
    def test_isolation_warning_constant_is_descriptive(self) -> None:
        assert "kernel-level isolation" in SandboxManager.ISOLATION_WARNING
        assert "gVisor" in SandboxManager.ISOLATION_WARNING
        assert "Firecracker" in SandboxManager.ISOLATION_WARNING

    def test_execute_emits_warning_on_non_linux(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        with patch("aumai_sandbox.core.platform.system", return_value="Windows"):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                mgr.execute(sandbox_id, ["python", "-c", "pass"], timeout=15.0)
        mgr.destroy(sandbox_id)
        assert any(
            SandboxManager.ISOLATION_WARNING in str(w.message) for w in recorded
        )

    def test_execute_emits_warning_for_seccomp_tier_on_linux(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        """Seccomp tier on Linux must still warn because no BPF filter is loaded."""
        seccomp_cap = CapabilityDeclaration(
            sandbox_tier=SandboxTier.seccomp,
            resource_limits=ResourceLimits(
                max_memory_mb=512,
                max_cpu_seconds=30.0,
                max_cost_usd=1.0,
                max_tokens=100_000,
            ),
            permissions=["read_env"],
        )
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(seccomp_cap)
        with patch("aumai_sandbox.core.platform.system", return_value="Linux"):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                mgr.execute(sandbox_id, ["python", "-c", "pass"], timeout=15.0)
        mgr.destroy(sandbox_id)
        assert any(
            SandboxManager.ISOLATION_WARNING in str(w.message) for w in recorded
        )

    def test_gvisor_on_linux_does_not_emit_isolation_warning(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        """gVisor on Linux is a real isolation backend and must NOT trigger the warning."""
        gvisor_cap = CapabilityDeclaration(
            sandbox_tier=SandboxTier.gvisor,
            resource_limits=ResourceLimits(
                max_memory_mb=512,
                max_cpu_seconds=30.0,
                max_cost_usd=1.0,
                max_tokens=100_000,
            ),
            permissions=["read_env"],
        )
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(gvisor_cap)
        # Mock both platform.system and the Popen call so runsc is never invoked.
        with patch("aumai_sandbox.core.platform.system", return_value="Linux"):
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = mock_popen.return_value.__enter__.return_value
                mock_proc.pid = 99999
                mock_proc.poll.return_value = 0
                mock_proc.returncode = 0
                mock_proc.communicate.return_value = (b"", b"")
                mock_popen.return_value.pid = 99999
                mock_popen.return_value.poll.return_value = 0
                mock_popen.return_value.returncode = 0
                mock_popen.return_value.communicate.return_value = (b"", b"")
                with warnings.catch_warnings(record=True) as recorded:
                    warnings.simplefilter("always")
                    try:
                        mgr.execute(
                            sandbox_id, ["python", "-c", "pass"], timeout=5.0
                        )
                    except Exception:
                        pass  # We only care about warnings, not execution success.
        mgr.destroy(sandbox_id)
        isolation_warnings = [
            w
            for w in recorded
            if SandboxManager.ISOLATION_WARNING in str(w.message)
        ]
        assert isolation_warnings == []


# ---------------------------------------------------------------------------
# S-C2: Command validation tests
# ---------------------------------------------------------------------------


class TestValidateCommand:
    def test_empty_command_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="must not be empty"):
            mgr._validate_command([])  # noqa: SLF001

    def test_semicolon_in_executable_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="shell metacharacters"):
            mgr._validate_command(["python;rm -rf /"])  # noqa: SLF001

    def test_pipe_in_executable_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="shell metacharacters"):
            mgr._validate_command(["python|bash"])  # noqa: SLF001

    def test_ampersand_in_executable_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="shell metacharacters"):
            mgr._validate_command(["python&evil"])  # noqa: SLF001

    def test_dollar_in_executable_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="shell metacharacters"):
            mgr._validate_command(["$PATH"])  # noqa: SLF001

    def test_backtick_in_executable_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="shell metacharacters"):
            mgr._validate_command(["`id`"])  # noqa: SLF001

    def test_newline_in_executable_raises(self) -> None:
        mgr = SandboxManager()
        with pytest.raises(SandboxError, match="shell metacharacters"):
            mgr._validate_command(["python\nrm"])  # noqa: SLF001

    def test_valid_known_command_does_not_raise(self) -> None:
        mgr = SandboxManager()
        mgr._validate_command(["python", "-c", "print('ok')"])  # noqa: SLF001

    def test_valid_node_command_does_not_raise(self) -> None:
        mgr = SandboxManager()
        mgr._validate_command(["node", "script.js"])  # noqa: SLF001

    def test_unknown_executable_does_not_raise(self) -> None:
        """An unknown executable triggers a log warning but is NOT blocked."""
        mgr = SandboxManager()
        # Should NOT raise — it only emits a log warning.
        mgr._validate_command(["some_custom_binary", "--flag"])  # noqa: SLF001

    def test_execute_empty_command_raises_sandbox_error(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        with pytest.raises(SandboxError, match="must not be empty"):
            mgr.execute(sandbox_id, [], timeout=5.0)
        mgr.destroy(sandbox_id)

    def test_execute_metachar_command_raises_sandbox_error(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(read_env_capability)
        with pytest.raises(SandboxError, match="shell metacharacters"):
            mgr.execute(sandbox_id, ["python;evil"], timeout=5.0)
        mgr.destroy(sandbox_id)


# ---------------------------------------------------------------------------
# S-C3: Environment filtering tests
# ---------------------------------------------------------------------------


class TestFilterEnvironment:
    def test_api_key_filtered(self) -> None:
        env = {"OPENAI_API_KEY": "sk-secret", "PATH": "/usr/bin"}
        result = _filter_environment(env)
        assert "OPENAI_API_KEY" not in result
        assert "PATH" in result

    def test_secret_suffix_filtered(self) -> None:
        env = {"DB_SECRET": "hunter2", "HOME": "/home/user"}
        result = _filter_environment(env)
        assert "DB_SECRET" not in result
        assert "HOME" in result

    def test_token_suffix_filtered(self) -> None:
        env = {"GITHUB_TOKEN": "ghp_abc", "USER": "agent"}
        result = _filter_environment(env)
        assert "GITHUB_TOKEN" not in result
        assert "USER" in result

    def test_password_suffix_filtered(self) -> None:
        env = {"DB_PASSWORD": "letmein", "PORT": "5432"}
        result = _filter_environment(env)
        assert "DB_PASSWORD" not in result
        assert "PORT" in result

    def test_credential_suffix_filtered(self) -> None:
        env = {"SERVICE_CREDENTIAL": "abc123", "HOST": "localhost"}
        result = _filter_environment(env)
        assert "SERVICE_CREDENTIAL" not in result
        assert "HOST" in result

    def test_aws_prefix_filtered(self) -> None:
        env = {"AWS_ACCESS_KEY_ID": "AKIA...", "AWS_SECRET_ACCESS_KEY": "...", "LANG": "en"}
        result = _filter_environment(env)
        assert "AWS_ACCESS_KEY_ID" not in result
        assert "AWS_SECRET_ACCESS_KEY" not in result
        assert "LANG" in result

    def test_azure_prefix_filtered(self) -> None:
        env = {"AZURE_CLIENT_SECRET": "...", "HOME": "/root"}
        result = _filter_environment(env)
        assert "AZURE_CLIENT_SECRET" not in result
        assert "HOME" in result

    def test_gcp_prefix_filtered(self) -> None:
        env = {"GCP_SERVICE_ACCOUNT": "...", "PATH": "/usr/bin"}
        result = _filter_environment(env)
        assert "GCP_SERVICE_ACCOUNT" not in result
        assert "PATH" in result

    def test_openai_prefix_filtered(self) -> None:
        env = {"OPENAI_API_BASE": "https://...", "USER": "agent"}
        result = _filter_environment(env)
        assert "OPENAI_API_BASE" not in result
        assert "USER" in result

    def test_anthropic_prefix_filtered(self) -> None:
        env = {"ANTHROPIC_API_KEY": "sk-ant-...", "TERM": "xterm"}
        result = _filter_environment(env)
        assert "ANTHROPIC_API_KEY" not in result
        assert "TERM" in result

    def test_empty_env_returns_empty(self) -> None:
        assert _filter_environment({}) == {}

    def test_all_safe_vars_preserved(self) -> None:
        env = {"PATH": "/usr/bin", "HOME": "/home/user", "LANG": "en_US.UTF-8"}
        result = _filter_environment(env)
        assert result == env

    def test_sensitive_patterns_constant_defined(self) -> None:
        assert "*_KEY" in _SENSITIVE_ENV_PATTERNS
        assert "AWS_*" in _SENSITIVE_ENV_PATTERNS
        assert "ANTHROPIC_*" in _SENSITIVE_ENV_PATTERNS


class TestBuildEnvironmentWithFiltering:
    def test_read_env_filters_sensitive_vars(self) -> None:
        """read_env must not pass AWS_* and similar keys to the subprocess."""
        import os

        cap = CapabilityDeclaration(permissions=["read_env"])
        mgr = SandboxManager()
        # Inject a fake sensitive variable into os.environ for the test.
        fake_env = dict(os.environ)
        fake_env["OPENAI_API_KEY"] = "sk-test-secret"
        fake_env["ANTHROPIC_API_KEY"] = "sk-ant-test"
        fake_env["PATH"] = fake_env.get("PATH", "/usr/bin")
        with patch("os.environ", fake_env):
            env = mgr._build_environment(cap)  # noqa: SLF001
        assert "OPENAI_API_KEY" not in env
        assert "ANTHROPIC_API_KEY" not in env
        assert "PATH" in env

    def test_read_env_with_allowlist_restricts_to_allowlist(self) -> None:
        import os

        cap = CapabilityDeclaration(
            permissions=["read_env"],
            env_allowlist=["PATH", "LANG"],
        )
        mgr = SandboxManager()
        fake_env = {
            "PATH": "/usr/bin",
            "LANG": "en_US.UTF-8",
            "HOME": "/home/user",
            "TERM": "xterm",
        }
        with patch("os.environ", fake_env):
            env = mgr._build_environment(cap)  # noqa: SLF001
        assert set(env.keys()) == {"PATH", "LANG"}

    def test_read_env_with_allowlist_still_filters_sensitive(self) -> None:
        """Even if a sensitive key appears in env_allowlist, it must be filtered."""
        cap = CapabilityDeclaration(
            permissions=["read_env"],
            env_allowlist=["OPENAI_API_KEY", "PATH"],
        )
        mgr = SandboxManager()
        fake_env = {"OPENAI_API_KEY": "sk-secret", "PATH": "/usr/bin"}
        with patch("os.environ", fake_env):
            env = mgr._build_environment(cap)  # noqa: SLF001
        assert "OPENAI_API_KEY" not in env
        assert "PATH" in env

    def test_no_read_env_ignores_allowlist(self) -> None:
        """Without read_env permission, env_allowlist has no effect — minimal env."""
        cap = CapabilityDeclaration(
            permissions=[],
            env_allowlist=["PATH", "HOME"],
        )
        mgr = SandboxManager()
        env = mgr._build_environment(cap)  # noqa: SLF001
        safe_keys = {"PATH", "PYTHONPATH", "SYSTEMROOT", "TEMP", "TMP", "HOME"}
        for key in env:
            assert key in safe_keys


# ---------------------------------------------------------------------------
# S-C3 model: env_allowlist field
# ---------------------------------------------------------------------------


class TestCapabilityDeclarationEnvAllowlist:
    def test_default_env_allowlist_is_none(self) -> None:
        cap = CapabilityDeclaration()
        assert cap.env_allowlist is None

    def test_env_allowlist_set(self) -> None:
        cap = CapabilityDeclaration(env_allowlist=["PATH", "HOME"])
        assert cap.env_allowlist == ["PATH", "HOME"]

    def test_env_allowlist_empty_list(self) -> None:
        cap = CapabilityDeclaration(env_allowlist=[])
        assert cap.env_allowlist == []

    def test_env_allowlist_round_trips_via_yaml(self) -> None:
        yaml_text = "permissions:\n  - read_env\nenv_allowlist:\n  - PATH\n  - LANG\n"
        cap = CapabilityParser.from_string(yaml_text)
        assert cap.env_allowlist == ["PATH", "LANG"]


# ---------------------------------------------------------------------------
# S-M2 + S-M3 regression tests
# ---------------------------------------------------------------------------


class TestMonitorAndTimeout:
    def test_timeout_is_not_reduced_by_cpu_limit(
        self, read_env_capability: CapabilityDeclaration
    ) -> None:
        """S-M3: effective_timeout must equal the caller-supplied timeout, not
        min(timeout, max_cpu * 2), so a slow command with a generous wall-clock
        timeout is not prematurely killed by an artificially small CPU-derived limit.
        """
        # max_cpu_seconds = 30.0, timeout = 10.0 — old code would have used
        # min(10.0, 60.0) = 10.0, which by coincidence matched, so use a case
        # where the old formula would differ: cpu=3.0, timeout=10.0.
        # Old formula: min(10.0, 6.0) = 6.0  →  would kill at 6s.
        # New formula: timeout = 10.0  →  correctly allows full 10s.
        cap = CapabilityDeclaration(
            resource_limits=ResourceLimits(
                max_cpu_seconds=3.0,
                max_memory_mb=512,
                max_cost_usd=1.0,
                max_tokens=100_000,
            ),
            permissions=["read_env"],
        )
        mgr = SandboxManager()
        sandbox_id = mgr.create_sandbox(cap)
        # Command that finishes quickly — we only want to confirm the timeout value
        # fed into _wait_with_limit_checks equals the caller-supplied timeout.
        with patch.object(
            mgr, "_wait_with_limit_checks", wraps=mgr._wait_with_limit_checks  # noqa: SLF001
        ) as mock_wait:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                mgr.execute(sandbox_id, ["python", "-c", "pass"], timeout=10.0)
        mgr.destroy(sandbox_id)
        _, kwargs = mock_wait.call_args
        assert kwargs["effective_timeout"] == 10.0
