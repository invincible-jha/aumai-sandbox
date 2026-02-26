"""Resource monitoring and limit enforcement for aumai-sandbox."""

from __future__ import annotations

import importlib
import threading
import time
import types
from typing import Any

from aumai_sandbox.models import ResourceLimits

# psutil is an optional dependency — load it at module import time so that
# the rest of the module stays type-clean (no per-call try/except).
_psutil_module: types.ModuleType | None = None
try:
    _psutil_module = importlib.import_module("psutil")
except ImportError:
    pass


class ResourceMonitor:
    """Track CPU time, memory, token spend, and USD cost for a sandbox.

    The monitor runs a background polling thread that periodically samples a
    subprocess (when a PID is registered).  It is intentionally kept simple
    and portable — it does not require ``psutil`` as a hard dependency; if
    ``psutil`` is available it will be used for accurate metrics, otherwise
    it falls back to best-effort counters.

    Usage::

        monitor = ResourceMonitor(limits)
        monitor.start(pid=proc.pid)
        # ... agent runs ...
        monitor.stop()
        ok, reason = monitor.check_limits()
        usage = monitor.snapshot()
    """

    _POLL_INTERVAL_SECONDS: float = 0.25

    def __init__(self, limits: ResourceLimits) -> None:
        self._limits = limits
        self._cpu_seconds: float = 0.0
        self._peak_memory_mb: float = 0.0
        self._tokens_used: int = 0
        self._cost_usd: float = 0.0
        self._start_time: float | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._pid: int | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, pid: int | None = None) -> None:
        """Begin monitoring.  Optionally attach to *pid* for OS-level metrics."""
        self._pid = pid
        self._start_time = time.monotonic()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name="resource-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background polling thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ------------------------------------------------------------------
    # Metric updates (called externally to record LLM usage)
    # ------------------------------------------------------------------

    def record_tokens(self, count: int) -> None:
        """Add *count* to the running token total."""
        with self._lock:
            self._tokens_used += count

    def record_cost(self, amount_usd: float) -> None:
        """Add *amount_usd* to the running cost total."""
        with self._lock:
            self._cost_usd += amount_usd

    def record_memory(self, memory_mb: float) -> None:
        """Update peak memory if *memory_mb* exceeds the current peak."""
        with self._lock:
            if memory_mb > self._peak_memory_mb:
                self._peak_memory_mb = memory_mb

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a point-in-time snapshot of all tracked metrics."""
        with self._lock:
            elapsed = (
                time.monotonic() - self._start_time if self._start_time is not None else 0.0
            )
            return {
                "cpu_seconds": round(self._cpu_seconds or elapsed, 3),
                "peak_memory_mb": round(self._peak_memory_mb, 2),
                "tokens_used": self._tokens_used,
                "cost_usd": round(self._cost_usd, 6),
                "elapsed_seconds": round(elapsed, 3),
            }

    def check_limits(self) -> tuple[bool, str | None]:
        """Return ``(within_limits, violation_message)``.

        Returns:
            A 2-tuple where the first element is ``True`` when all limits are
            satisfied, and the second element is a human-readable violation
            message or ``None``.
        """
        return check_limits(self.snapshot(), self._limits)

    # ------------------------------------------------------------------
    # Background polling
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Continuously sample the monitored process until stopped."""
        while not self._stop_event.wait(self._POLL_INTERVAL_SECONDS):
            self._sample()

    def _sample(self) -> None:
        """Take one resource sample; uses psutil when available."""
        if self._pid is None or _psutil_module is None:
            return
        try:
            proc = _psutil_module.Process(self._pid)
            cpu = proc.cpu_times()
            mem = proc.memory_info()
            with self._lock:
                self._cpu_seconds = cpu.user + cpu.system
                memory_mb = mem.rss / (1024 * 1024)
                if memory_mb > self._peak_memory_mb:
                    self._peak_memory_mb = memory_mb
        except Exception:
            # Process ended or access denied — ignore.
            pass


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------


def check_limits(
    current: dict[str, Any], limits: ResourceLimits
) -> tuple[bool, str | None]:
    """Check *current* resource metrics against *limits*.

    Args:
        current: Dict with keys ``cpu_seconds``, ``peak_memory_mb``,
                 ``tokens_used``, ``cost_usd``.  Missing keys are treated as 0.
        limits: :class:`~aumai_sandbox.models.ResourceLimits` thresholds.

    Returns:
        ``(True, None)`` when all metrics are within limits, otherwise
        ``(False, human_readable_reason)``.
    """
    cpu_seconds: float = float(current.get("cpu_seconds", 0))
    peak_memory_mb: float = float(current.get("peak_memory_mb", 0))
    tokens_used: int = int(current.get("tokens_used", 0))
    cost_usd: float = float(current.get("cost_usd", 0))

    if cpu_seconds > limits.max_cpu_seconds:
        return False, (
            f"CPU limit exceeded: {cpu_seconds:.2f}s used, "
            f"limit is {limits.max_cpu_seconds:.2f}s"
        )

    if peak_memory_mb > limits.max_memory_mb:
        return False, (
            f"Memory limit exceeded: {peak_memory_mb:.1f} MiB used, "
            f"limit is {limits.max_memory_mb} MiB"
        )

    if tokens_used > limits.max_tokens:
        return False, (
            f"Token limit exceeded: {tokens_used} tokens used, "
            f"limit is {limits.max_tokens}"
        )

    if cost_usd > limits.max_cost_usd:
        return False, (
            f"Cost limit exceeded: ${cost_usd:.4f} spent, "
            f"limit is ${limits.max_cost_usd:.4f}"
        )

    return True, None


__all__ = ["ResourceMonitor", "check_limits"]
