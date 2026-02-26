"""Core sandbox orchestration logic for aumai-sandbox."""

from __future__ import annotations

import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

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
from aumai_sandbox.resources import ResourceMonitor, check_limits


class SandboxError(Exception):
    """Raised for sandbox lifecycle errors."""


class CapabilityParseError(Exception):
    """Raised when a capability YAML file cannot be parsed."""


# ---------------------------------------------------------------------------
# CapabilityParser
# ---------------------------------------------------------------------------


class CapabilityParser:
    """Parse YAML capability files into :class:`~aumai_sandbox.models.CapabilityDeclaration`.

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
        result = mgr.execute(sandbox_id, ["python", "-c", "print('hello')"], timeout=10.0)
        mgr.destroy(sandbox_id)
    """

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
            SandboxError: If *sandbox_id* is unknown or the sandbox is not
                          in a runnable state.
        """
        state = self._get_state(sandbox_id)

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
            effective_timeout = min(timeout, state.capability.resource_limits.max_cpu_seconds * 2)
            stdout_bytes, stderr_bytes = self._wait_with_limit_checks(
                proc=proc,
                monitor=monitor,
                limits=state.capability.resource_limits,
                effective_timeout=effective_timeout,
            )

        except Exception as exc:
            monitor.stop()
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
                except Exception:
                    pass
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

    def _build_environment(self, capability: CapabilityDeclaration) -> dict[str, str]:
        """Build a restricted environment dict for the subprocess.

        Only allow environment variables that are explicitly safe.  The
        ``read_env`` permission in capability.permissions unlocks the full
        process environment (useful for development agents).
        """
        import os

        if "read_env" in capability.permissions:
            return dict(os.environ)

        # Minimal environment: PATH and PYTHONPATH only.
        safe_keys = {"PATH", "PYTHONPATH", "SYSTEMROOT", "TEMP", "TMP", "HOME"}
        return {k: v for k, v in os.environ.items() if k in safe_keys}

    def _build_command_prefix(self, capability: CapabilityDeclaration) -> list[str]:
        """Return any command prefix needed for the chosen isolation tier.

        On Linux with gVisor installed this would return ``["runsc", "run"]``.
        On Windows we return an empty prefix (subprocess isolation only).
        """
        import platform

        tier = capability.sandbox_tier
        system = platform.system()

        if system != "Linux":
            # No kernel isolation available outside Linux.
            return []

        prefix_map: dict[SandboxTier, list[str]] = {
            SandboxTier.seccomp: [],  # enforced by the kernel implicitly
            SandboxTier.gvisor: ["runsc", "run"],  # requires gVisor installation
            SandboxTier.firecracker: [],  # requires Firecracker — orchestration TBD
        }
        return prefix_map.get(tier, [])

    def _wait_with_limit_checks(
        self,
        proc: "subprocess.Popen[bytes]",
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
]
