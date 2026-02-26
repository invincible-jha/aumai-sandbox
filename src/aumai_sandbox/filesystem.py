"""Filesystem isolation policy enforcement for aumai-sandbox."""

from __future__ import annotations

import os
import pathlib

from aumai_sandbox.models import FilesystemConfig, FilesystemMode


class FilesystemPolicy:
    """Enforce read-only / read-write / no-access rules for path access.

    This is a logic-layer validator.  It does not perform OS-level isolation
    by itself; it is intended to be called *before* any file operation so that
    the sandbox orchestrator can reject or allow the operation.

    Example::

        config = FilesystemConfig(
            mode=FilesystemMode.read_write,
            writable_paths=["/tmp/agent_work"],
        )
        policy = FilesystemPolicy(config)
        assert policy.can_read("/etc/passwd")
        assert not policy.can_write("/etc/passwd")
        assert policy.can_write("/tmp/agent_work/output.txt")
    """

    def __init__(self, config: FilesystemConfig) -> None:
        self._config = config

    def can_read(self, path: str) -> bool:
        """Return True when *path* may be read under this policy."""
        return validate_path_access(path, "read", self._config)

    def can_write(self, path: str) -> bool:
        """Return True when *path* may be written under this policy."""
        return validate_path_access(path, "write", self._config)

    def deny_reason(self, path: str, mode: str) -> str | None:
        """Return a human-readable denial reason, or None if access is allowed."""
        if validate_path_access(path, mode, self._config):
            return None
        fs_mode = self._config.mode
        if fs_mode == FilesystemMode.none:
            return f"filesystem access is disabled (mode=none); denied {mode} on '{path}'"
        if mode == "write" and fs_mode == FilesystemMode.read_only:
            return f"sandbox is read-only; denied write on '{path}'"
        if mode == "write":
            normalized = _normalize(path)
            allowed = [_normalize(p) for p in self._config.writable_paths]
            return (
                f"path '{path}' is not under any writable_paths "
                f"({allowed}); denied write"
            )
        return f"access denied for {mode} on '{path}'"


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------


def validate_path_access(path: str, mode: str, config: FilesystemConfig) -> bool:
    """Return True when *path* is accessible in *mode* under *config*.

    Args:
        path: Filesystem path to evaluate (need not exist).
        mode: ``"read"`` or ``"write"``.
        config: :class:`~aumai_sandbox.models.FilesystemConfig` policy.

    Returns:
        ``True`` if the operation is permitted, ``False`` otherwise.

    Raises:
        ValueError: If *mode* is not ``"read"`` or ``"write"``.
    """
    if mode not in ("read", "write"):
        raise ValueError(f"mode must be 'read' or 'write', got '{mode}'")

    filesystem_mode = config.mode

    if filesystem_mode == FilesystemMode.none:
        return False

    if mode == "read":
        # read_only and read_write both permit reads.
        return True

    # mode == "write"
    if filesystem_mode == FilesystemMode.read_only:
        return False

    # read_write: allow only paths under one of the declared writable_paths.
    if not config.writable_paths:
        # read_write with no explicit paths — allow all writes.
        return True

    normalized_target = _normalize(path)
    for allowed_prefix in config.writable_paths:
        normalized_prefix = _normalize(allowed_prefix)
        # pathlib.is_relative_to covers exact match and proper subdirectories.
        try:
            normalized_target.is_relative_to(normalized_prefix)
            if normalized_target == normalized_prefix or normalized_target.is_relative_to(
                normalized_prefix
            ):
                return True
        except AttributeError:
            # Python < 3.9 fallback (is_relative_to added in 3.9)
            try:
                normalized_target.relative_to(normalized_prefix)
                return True
            except ValueError:
                pass

    return False


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _normalize(path: str) -> pathlib.PurePosixPath:
    """Normalize *path* for comparison (resolve ``..`` etc.)."""
    # Use os.path.normpath for cross-platform normalization then convert.
    normalized = os.path.normpath(path).replace("\\", "/")
    return pathlib.PurePosixPath(normalized)


__all__ = ["FilesystemPolicy", "validate_path_access"]
