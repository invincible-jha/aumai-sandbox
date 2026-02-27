"""Core sandbox orchestration logic for aumai-sandbox."""

from __future__ import annotations

import fnmatch
import logging
import os
import platform
import subprocess
import threading
import time
import uuid
import warnings
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from aumai_sandbox.models import (
    CapabilityDeclaration,
    ResourceLimits,
    SandboxResult,
    SandboxStatus,
    SandboxTier,
)
from aumai_sandbox.resources import ResourceMonitor

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive environment variable patterns (fnmatch-style)
# ---------------------------------------------------------------------------

_SENSITIVE_ENV_PATTERNS: tuple[str, ...] = (
    "*_KEY",
    "*_SECRET",
    "*_TOKEN",
    "*_PASSWORD",
    "*_CREDENTIAL",
    "AWS_*",
    "AZURE_*",
    "GCP_*",
    "OPENAI_*",
    "ANTHROPIC_*",
)


class SandboxError(Exception):
    """Raised for sandbox lifecycle errors."""


class CapabilityParseError(Exception):
    """Raised when a capability YAML file cannot be parsed."""


# ---------------------------------------------------------------------------
# Environment filtering
# ---------------------------------------------------------------------------


def _filter_environment(env: dict[str, str]) -> dict[str, str]:
    """Return *env* with all sensitive variables removed.

    Variables are filtered when their name matches any pattern in
    :data:`_SENSITIVE_ENV_PATTERNS` using case-sensitive :func:`fnmatch.fnmatch`.

    Args:
        env: Source environment mapping (typically ``dict(os.environ)``).

    Returns:
        A new dict that contains no keys matching a sensitive pattern.
    """
    filtered: dict[str, str] = {}
    for key, value in env.items():
        is_sensitive = any(
            fnmatch.fnmatch(key, pattern) for pattern in _SENSITIVE_ENV_PATTERNS
        )
        if not is_sensitive:
            filtered[key] = value
    return filtered


# ---------------------------------------------------------------------------
# CapabilityParser
# ---------------------------------------------------------------------------


class CapabilityParser:
    """Parse YAML capability files into CapabilityDeclaration objects.

    Expected YAML shape::

        sandbox_tier: gvisor
        resource_limits:
          max_memory_mb: 256
          max_cpu_seconds: 10.0
          max_cost_usd: 0.05
          max_tokens: 50000
        network_egress_rules:
          - domain: "api.openai.com"
            ports: [443]
            rate_limit_per_min: 30
        filesystem_config:
          mode: read_only
        permissions:
          - read_env

    All fields are optional and fall back to their Pydantic defaults.
    """

    @staticmethod
    def from_file(path: str | Path) -> CapabilityDeclaration:
        """Load and parse a capability YAML file.

        Args:
            path: Filesystem path to the YAML file.

        Returns:
            A validated :class:`CapabilityDeclaration`.

        Raises:
            CapabilityParseError: If the file cannot be read or is invalid.
        """
        file_path = Path(path)
        if not file_path.exists():
            raise CapabilityParseError(f"capability file not found: {file_path}")
        if not file_path.is_file():
            raise CapabilityParseError(f"path is not a file: {file_path}")

        try:
            raw_text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CapabilityParseError(f"cannot read capability file: {exc}") from exc

        return CapabilityParser.from_string(raw_text)

    @staticmethod
    def from_string(yaml_text: str) -> CapabilityDeclaration:
        """Parse a YAML string into a :class:`CapabilityDeclaration`.

        Args:
            yaml_text: Raw YAML content.

        Returns:
            A validated :class:`CapabilityDeclaration`.

        Raises:
            CapabilityParseError: If the YAML is malformed or fails validation.
        """
        try:
            data: Any = yaml.safe_load(yaml_text)
        except yaml.YAMLError as exc:
            raise CapabilityParseError(f"YAML parse error: {exc}") from exc

        if data is None:
            # Empty YAML — use all defaults.
            data = {}

        if not isinstance(data, dict):
            raise CapabilityParseError(
                f"capability file must be a YAML mapping, got {type(data).__name__}"
            )

        try:
            return CapabilityDeclaration.model_validate(data)
        except ValidationError as exc:
            raise CapabilityParseError(f"capability validation error: {exc}") from exc


# ---------------------------------------------------------------------------
# Internal sandbox state
# ---------------------------------------------------------------------------


class _SandboxState:
    """Mutable runtime state for a single sandbox instance."""

    def __init__(self, sandbox_id: str, capability: CapabilityDeclaration) -> None:
        self.sandbox_id = sandbox_id
        self.capability = capability
        self.status = SandboxStatus.created
        self.process: subprocess.Popen[bytes] | None = None
        self.monitor: ResourceMonitor | None = None
        self.lock = threading.Lock()


# ---------------------------------------------------------------------------
# SandboxManager
# ---------------------------------------------------------------------------


class SandboxManager:
    """Create, execute, and destroy isolated sandbox environments.

    Since real Linux kernel features (seccomp, gVisor, Firecracker) are not
    available on Windows, this manager implements the *orchestration layer*:

    - It enforces resource limits via :class:`~aumai_sandbox.resources.ResourceMonitor`.
    - It applies filesystem policy checks before command execution.
    - It uses ``subprocess`` with restricted environment variables as a
      portable isolation fallback.
    - On Linux a future backend can swap in gVisor/Firecracker by overriding
      ``_build_command_prefix``.

    Example::

        mgr = SandboxManager()
        capability = CapabilityDeclaration(
            resource_limits=ResourceLimits(max_cpu_seconds=5.0)
        )
        sandbox_id = mgr.create_sandbox(capability)
        result = mgr.execute(
            sandbox_id, ["python", "-c", "print('hello')"], timeout=10.0
        )
        mgr.destroy(sandbox_id)
    """

    ISOLATION_WARNING: str = (
        "No kernel-level isolation is enforced in this implementation. "
        "The sandbox provides policy orchestration only. "
        "For production use, deploy with gVisor or Firecracker."
    )

    # Shell metacharacters that must not appear in command[0] (the executable).
    _SHELL_METACHARACTERS: frozenset[str] = frozenset(";|&$`\n")

    # Known safe executables — command[0] values outside this set trigger a log
    # warning but are NOT blocked (enforcement is advisory).
    _KNOWN_EXECUTABLES: frozenset[str] = frozenset(
        {"python", "python3", "node", "bash", "sh"}
    )

    def __init__(self) -> None:
        self._sandboxes: dict[str, _SandboxState] = {}
        self._global_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def create_sandbox(self, capability: CapabilityDeclaration) -> str:
        """Register a new sandbox and return its unique ID.

        Args:
            capability: Policy governing this sandbox.

        Returns:
            A UUID string that identifies this sandbox.
        """
        sandbox_id = str(uuid.uuid4())
        state = _SandboxState(sandbox_id=sandbox_id, capability=capability)
        with self._global_lock:
            self._sandboxes[sandbox_id] = state
        return sandbox_id

    def execute(
        self,
        sandbox_id: str,
        command: list[str],
        timeout: float = 30.0,
    ) -> SandboxResult:
        """Run *command* inside the sandbox and return the result.

        The sandbox tier controls how isolation is applied:

        - ``seccomp``: subprocess with filtered environment variables.
        - ``gvisor``: subprocess (fallback; gVisor not available on Windows).
        - ``firecracker``: subprocess (fallback; Firecracker not available on Windows).

        Resource limits are enforced via the background
        :class:`~aumai_sandbox.resources.ResourceMonitor`.  If a limit is
        breached the process is terminated and the result reflects a non-zero
        exit code.

        Args:
            sandbox_id: ID returned by :meth:`create_sandbox`.
            command: Argv list, e.g. ``["python", "agent.py", "--arg", "val"]``.
            timeout: Wall-clock timeout in seconds; overrides nothing in the
                     capability but acts as an additional safety net.

        Returns:
            :class:`~aumai_sandbox.models.SandboxResult` with stdout, stderr,
            exit code, duration, and resource usage.

        Raises:
            SandboxError: If *sandbox_id* is unknown, the sandbox is not
                          in a runnable state, or *command* fails validation.
        """
        # S-C2: Validate command before any subprocess work.
        self._validate_command(command)

        state = self._get_state(sandbox_id)

        # S-C1: Warn when no real kernel-level isolation is available.
        tier = state.capability.sandbox_tier
        system = platform.system()
        if system != "Linux" or tier == SandboxTier.seccomp:
            warnings.warn(self.ISOLATION_WARNING, stacklevel=2)
            _logger.warning(self.ISOLATION_WARNING)

        with state.lock:
            if state.status not in (SandboxStatus.created, SandboxStatus.stopped):
                raise SandboxError(
                    f"sandbox {sandbox_id} is in state '{state.status.value}'; "
                    "only 'created' or 'stopped' sandboxes can execute commands"
                )
            state.status = SandboxStatus.running

        start = time.monotonic()
        monitor = ResourceMonitor(state.capability.resource_limits)

        try:
            proc_env = self._build_environment(state.capability)
            cmd_with_prefix = self._build_command_prefix(state.capability) + command

            # S-H1: Log filesystem policy advisory check (non-blocking).
            self._log_filesystem_policy_advisory(command, state.capability)

            proc = subprocess.Popen(  # noqa: S603
                cmd_with_prefix,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=proc_env,
            )

            with state.lock:
                state.process = proc

            monitor.start(pid=proc.pid)

            # Poll: enforce resource limits during execution.
            # S-M3: Use timeout directly; CPU enforcement is handled by ResourceMonitor.
            stdout_bytes, stderr_bytes = self._wait_with_limit_checks(
                proc=proc,
                monitor=monitor,
                limits=state.capability.resource_limits,
                effective_timeout=timeout,
            )

        except SandboxError:
            # Re-raise SandboxError (e.g. from _validate_command) without wrapping.
            raise
        except Exception as exc:
            # S-M2: monitor.stop() is only in finally — removed duplicate here.
            elapsed_ms = (time.monotonic() - start) * 1000
            with state.lock:
                state.status = SandboxStatus.failed
                state.process = None
            return SandboxResult(
                exit_code=-1,
                stdout="",
                stderr=f"sandbox execution error: {exc}",
                duration_ms=round(elapsed_ms, 2),
                resource_usage=monitor.snapshot(),
            )
        finally:
            monitor.stop()

        elapsed_ms = (time.monotonic() - start) * 1000
        exit_code = proc.returncode if proc.returncode is not None else -1

        with state.lock:
            state.status = SandboxStatus.stopped
            state.process = None

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_ms=round(elapsed_ms, 2),
            resource_usage=monitor.snapshot(),
        )

    def destroy(self, sandbox_id: str) -> None:
        """Terminate and remove a sandbox.

        Kills any running process, then removes the sandbox from the registry.

        Args:
            sandbox_id: ID of the sandbox to destroy.

        Raises:
            SandboxError: If *sandbox_id* does not exist.
        """
        state = self._get_state(sandbox_id)
        with state.lock:
            if state.process is not None:
                try:
                    state.process.kill()
                    state.process.wait(timeout=5.0)
                except Exception:  # noqa: BLE001,S110
                    pass  # Process already dead or permission denied — safe to ignore.
                state.process = None
            state.status = SandboxStatus.stopped

        with self._global_lock:
            self._sandboxes.pop(sandbox_id, None)

    def status(self, sandbox_id: str) -> SandboxStatus:
        """Return the current :class:`~aumai_sandbox.models.SandboxStatus`."""
        return self._get_state(sandbox_id).status

    def list_sandboxes(self) -> list[dict[str, Any]]:
        """Return summary info for all tracked sandboxes."""
        with self._global_lock:
            return [
                {
                    "sandbox_id": state.sandbox_id,
                    "status": state.status.value,
                    "tier": state.capability.sandbox_tier.value,
                }
                for state in self._sandboxes.values()
            ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_state(self, sandbox_id: str) -> _SandboxState:
        with self._global_lock:
            state = self._sandboxes.get(sandbox_id)
        if state is None:
            raise SandboxError(f"unknown sandbox id: {sandbox_id}")
        return state

    def _validate_command(self, command: list[str]) -> None:
        """Validate *command* before subprocess execution.

        Args:
            command: The argv list to validate.

        Raises:
            SandboxError: If the command is empty or command[0] contains shell
                          metacharacters that indicate a shell-injection attempt.
        """
        if not command:
            raise SandboxError("command must not be empty")

        executable = command[0]
        found_meta = [ch for ch in self._SHELL_METACHARACTERS if ch in executable]
        if found_meta:
            raise SandboxError(
                f"command executable contains disallowed shell metacharacters "
                f"{found_meta!r}: {executable!r}"
            )

        if executable not in self._KNOWN_EXECUTABLES:
            _logger.warning(
                "command executable %r is not in the set of known-safe executables %r; "
                "proceeding but verify the binary is trusted",
                executable,
                sorted(self._KNOWN_EXECUTABLES),
            )

    def _build_environment(self, capability: CapabilityDeclaration) -> dict[str, str]:
        """Build a restricted environment dict for the subprocess.

        Only allow environment variables that are explicitly safe.  When the
        ``read_env`` permission is granted the full process environment is passed
        through, but all variables matching :data:`_SENSITIVE_ENV_PATTERNS` are
        always filtered out.  If ``capability.env_allowlist`` is set, only those
        specific variable names survive (after sensitive-pattern filtering).
        """
        if "read_env" in capability.permissions:
            filtered = _filter_environment(dict(os.environ))
            if capability.env_allowlist is not None:
                allowlist_set = set(capability.env_allowlist)
                filtered = {k: v for k, v in filtered.items() if k in allowlist_set}
            return filtered

        # Minimal environment: PATH and PYTHONPATH only.
        safe_keys = {"PATH", "PYTHONPATH", "SYSTEMROOT", "TEMP", "TMP", "HOME"}
        return {k: v for k, v in os.environ.items() if k in safe_keys}

    def _build_command_prefix(self, capability: CapabilityDeclaration) -> list[str]:
        """Return any command prefix needed for the chosen isolation tier.

        On Linux with gVisor installed this would return ``["runsc", "run"]``.
        On Windows we return an empty prefix (subprocess isolation only).

        NOTE: Seccomp and Firecracker tiers do not yet apply a real kernel
        filter via this implementation — a TODO for a future Linux backend.
        """
        tier = capability.sandbox_tier
        system = platform.system()

        if system != "Linux":
            # No kernel isolation available outside Linux.
            return []

        prefix_map: dict[SandboxTier, list[str]] = {
            # TODO: Apply an actual seccomp-bpf filter profile here; currently
            # no filter is loaded, so this tier provides no kernel restriction.
            SandboxTier.seccomp: [],
            SandboxTier.gvisor: ["runsc", "run"],  # requires gVisor installation
            # TODO: Wire up Firecracker VM launch; currently falls back to
            # subprocess with no VM isolation.
            SandboxTier.firecracker: [],
        }
        return prefix_map.get(tier, [])

    def _log_filesystem_policy_advisory(
        self,
        command: list[str],
        capability: CapabilityDeclaration,
    ) -> None:
        """Log an advisory warning if the command touches paths outside policy.

        This is a pre-flight advisory check only; it does NOT block execution.
        Runtime enforcement requires OS-level isolation (chroot, mount namespaces).
        """
        from aumai_sandbox.filesystem import FilesystemPolicy

        policy = FilesystemPolicy(capability.filesystem_config)
        # Inspect argv entries that look like file paths (contain a path separator
        # or start with / or .) as a heuristic — not exhaustive.
        for arg in command[1:]:
            if "/" in arg or arg.startswith(".") or (len(arg) > 2 and arg[1] == ":"):
                if not policy.can_read(arg):
                    reason = policy.deny_reason(arg, "read")
                    _logger.warning(
                        "[advisory] filesystem policy would deny read access to %r: %s",
                        arg,
                        reason,
                    )
                if not policy.can_write(arg):
                    reason = policy.deny_reason(arg, "write")
                    _logger.warning(
                        "[advisory] filesystem policy would deny write access to %r: %s",
                        arg,
                        reason,
                    )

    def _wait_with_limit_checks(
        self,
        proc: subprocess.Popen[bytes],
        monitor: ResourceMonitor,
        limits: ResourceLimits,
        effective_timeout: float,
    ) -> tuple[bytes, bytes]:
        """Wait for *proc* to finish while enforcing resource limits.

        Polls every 250ms; if a limit is exceeded or *effective_timeout* is
        reached the process is killed.

        Returns:
            ``(stdout_bytes, stderr_bytes)`` from the process.
        """
        poll_interval = 0.25
        deadline = time.monotonic() + effective_timeout
        violation: str | None = None

        while proc.poll() is None:
            now = time.monotonic()
            if now >= deadline:
                violation = f"wall-clock timeout of {effective_timeout:.1f}s exceeded"
                break

            within_limits, reason = monitor.check_limits()
            if not within_limits:
                violation = reason
                break

            remaining = deadline - now
            time.sleep(min(poll_interval, remaining))

        if violation is not None:
            try:
                proc.kill()
            except OSError:
                pass
            # Drain pipes after kill.
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=5.0)
            except Exception:
                stdout_bytes, stderr_bytes = b"", b""
            # Embed the violation in stderr so callers can surface it.
            stderr_bytes = stderr_bytes + f"\n[sandbox] killed: {violation}".encode()
            return stdout_bytes, stderr_bytes

        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_bytes, stderr_bytes = proc.communicate()

        return stdout_bytes, stderr_bytes


__all__ = [
    "CapabilityParseError",
    "CapabilityParser",
    "SandboxError",
    "SandboxManager",
    "_filter_environment",
    "_SENSITIVE_ENV_PATTERNS",
]
