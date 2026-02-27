"""Tests for aumai_sandbox.filesystem — path access policy enforcement."""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from aumai_sandbox.filesystem import (
    FilesystemPolicy,
    _normalize,
    validate_path_access,
)
from aumai_sandbox.models import FilesystemConfig, FilesystemMode

# ---------------------------------------------------------------------------
# _normalize helper
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_simple_absolute_path(self) -> None:
        import pathlib

        result = _normalize("/tmp/agent/output.txt")
        # PurePath uses OS-native separators; compare parts for portability.
        assert isinstance(result, pathlib.PurePath)
        assert "agent" in result.parts
        assert "output.txt" in result.parts

    def test_dotdot_resolved(self) -> None:
        result = _normalize("/tmp/agent/../other/output.txt")
        # Dot-dot must have been resolved — "agent" should NOT appear in parts.
        assert "agent" not in result.parts
        assert "other" in result.parts
        assert "output.txt" in result.parts

    def test_trailing_slash_removed(self) -> None:
        result = _normalize("/tmp/agent/")
        assert "agent" in str(result)

    def test_backslash_converted(self) -> None:
        # Windows-style paths should be representable as a PurePath without error.
        import pathlib

        result = _normalize("C:\\Users\\agent\\output.txt")
        assert isinstance(result, pathlib.PurePath)
        # The path must contain the expected components.
        assert "agent" in result.parts
        assert "output.txt" in result.parts


# ---------------------------------------------------------------------------
# validate_path_access
# ---------------------------------------------------------------------------


class TestValidatePathAccess:
    # --- none mode ---

    def test_none_mode_denies_read(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.none)
        assert validate_path_access("/etc/passwd", "read", config) is False

    def test_none_mode_denies_write(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.none)
        assert validate_path_access("/tmp/output.txt", "write", config) is False

    # --- read_only mode ---

    def test_read_only_allows_read(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        assert validate_path_access("/etc/passwd", "read", config) is True

    def test_read_only_denies_write(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        assert validate_path_access("/etc/passwd", "write", config) is False

    def test_read_only_denies_write_any_path(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        assert validate_path_access("/tmp/output.txt", "write", config) is False

    # --- read_write mode, no explicit paths ---

    def test_read_write_no_paths_allows_read(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_write, writable_paths=[])
        assert validate_path_access("/etc/passwd", "read", config) is True

    def test_read_write_no_paths_allows_any_write(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_write, writable_paths=[])
        assert validate_path_access("/anywhere/output.txt", "write", config) is True

    # --- read_write mode, with explicit paths ---

    def test_read_write_with_paths_allows_matching_write(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent_work"],
        )
        result = validate_path_access("/tmp/agent_work/result.json", "write", config)
        assert result is True

    def test_read_write_with_paths_allows_exact_path_write(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent_work"],
        )
        assert validate_path_access("/tmp/agent_work", "write", config) is True

    def test_read_write_with_paths_denies_outside_write(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent_work"],
        )
        assert validate_path_access("/home/user/.ssh/id_rsa", "write", config) is False

    def test_read_write_with_paths_allows_read_anywhere(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent_work"],
        )
        assert validate_path_access("/etc/hosts", "read", config) is True

    def test_read_write_multiple_paths(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent", "/var/agent/output"],
        )
        assert validate_path_access("/tmp/agent/data.csv", "write", config) is True
        var_result = validate_path_access(
            "/var/agent/output/report.txt", "write", config
        )
        assert var_result is True
        assert validate_path_access("/etc/shadow", "write", config) is False

    def test_path_traversal_blocked(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent_work"],
        )
        # Path traversal attempt: resolve should stay outside /tmp/agent_work
        result = validate_path_access(
            "/tmp/agent_work/../../../etc/passwd", "write", config
        )
        assert result is False

    # --- invalid mode argument ---

    def test_invalid_mode_raises_value_error(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        with pytest.raises(ValueError, match="mode must be 'read' or 'write'"):
            validate_path_access("/tmp/file", "execute", config)

    def test_invalid_mode_delete_raises(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        with pytest.raises(ValueError):
            validate_path_access("/tmp/file", "delete", config)


# ---------------------------------------------------------------------------
# FilesystemPolicy
# ---------------------------------------------------------------------------


class TestFilesystemPolicy:
    def test_can_read_delegates_correctly(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        policy = FilesystemPolicy(config)
        assert policy.can_read("/etc/passwd") is True

    def test_can_write_delegates_correctly(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        policy = FilesystemPolicy(config)
        assert policy.can_write("/etc/passwd") is False

    def test_can_write_allowed_path(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent"],
        )
        policy = FilesystemPolicy(config)
        assert policy.can_write("/tmp/agent/output.txt") is True

    def test_deny_reason_returns_none_when_allowed(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        policy = FilesystemPolicy(config)
        reason = policy.deny_reason("/etc/passwd", "read")
        assert reason is None

    def test_deny_reason_none_mode(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.none)
        policy = FilesystemPolicy(config)
        reason = policy.deny_reason("/etc/passwd", "read")
        assert reason is not None
        assert "none" in reason.lower()

    def test_deny_reason_read_only_write(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        policy = FilesystemPolicy(config)
        reason = policy.deny_reason("/etc/passwd", "write")
        assert reason is not None
        assert "read-only" in reason.lower()

    def test_deny_reason_write_outside_allowed_paths(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent"],
        )
        policy = FilesystemPolicy(config)
        reason = policy.deny_reason("/home/user/secret", "write")
        assert reason is not None
        assert "writable_paths" in reason

    def test_deny_reason_allowed_write_returns_none(self) -> None:
        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent"],
        )
        policy = FilesystemPolicy(config)
        reason = policy.deny_reason("/tmp/agent/output.json", "write")
        assert reason is None

    def test_none_mode_deny_reason_contains_path(self) -> None:
        config = FilesystemConfig(mode=FilesystemMode.none)
        policy = FilesystemPolicy(config)
        reason = policy.deny_reason("/secret/path", "write")
        assert reason is not None
        assert "/secret/path" in reason


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------


_PATH_ALPHABET = st.characters(
    whitelist_categories=("Lu", "Ll", "Nd"),
    whitelist_characters="/_.-",
)
_PATH_STRATEGY = st.text(min_size=1, alphabet=_PATH_ALPHABET)


class TestFilesystemPropertyBased:
    @given(path=_PATH_STRATEGY)
    @settings(max_examples=50)
    def test_read_only_always_allows_read(self, path: str) -> None:
        """read_only mode must allow reads for any path string."""
        assume(path.strip())
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        assert validate_path_access(path, "read", config) is True

    @given(path=_PATH_STRATEGY)
    @settings(max_examples=50)
    def test_none_mode_always_denies(self, path: str) -> None:
        """none mode must deny reads and writes for any path string."""
        assume(path.strip())
        config = FilesystemConfig(mode=FilesystemMode.none)
        assert validate_path_access(path, "read", config) is False
        assert validate_path_access(path, "write", config) is False

    @given(path=_PATH_STRATEGY)
    @settings(max_examples=50)
    def test_read_only_never_allows_write(self, path: str) -> None:
        """read_only mode must never allow writes."""
        assume(path.strip())
        config = FilesystemConfig(mode=FilesystemMode.read_only)
        assert validate_path_access(path, "write", config) is False
