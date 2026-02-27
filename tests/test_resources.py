"""Tests for aumai_sandbox.resources — ResourceMonitor and check_limits."""

from __future__ import annotations

import threading
import time
from typing import Any
from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from aumai_sandbox.models import ResourceLimits
from aumai_sandbox.resources import ResourceMonitor, check_limits

# ---------------------------------------------------------------------------
# check_limits — module-level helper
# ---------------------------------------------------------------------------


class TestCheckLimits:
    def test_all_within_limits_returns_true_none(self) -> None:
        limits = ResourceLimits(
            max_memory_mb=512,
            max_cpu_seconds=30.0,
            max_cost_usd=0.10,
            max_tokens=100_000,
        )
        usage: dict[str, Any] = {
            "cpu_seconds": 5.0,
            "peak_memory_mb": 100.0,
            "tokens_used": 1000,
            "cost_usd": 0.01,
        }
        ok, reason = check_limits(usage, limits)
        assert ok is True
        assert reason is None

    def test_cpu_exceeded(self) -> None:
        limits = ResourceLimits(max_cpu_seconds=10.0)
        usage: dict[str, Any] = {
            "cpu_seconds": 15.0, "peak_memory_mb": 0, "tokens_used": 0, "cost_usd": 0
        }
        ok, reason = check_limits(usage, limits)
        assert ok is False
        assert reason is not None
        assert "CPU" in reason
        assert "15.00" in reason

    def test_memory_exceeded(self) -> None:
        limits = ResourceLimits(max_memory_mb=512)
        usage: dict[str, Any] = {
            "cpu_seconds": 0, "peak_memory_mb": 600.0, "tokens_used": 0, "cost_usd": 0
        }
        ok, reason = check_limits(usage, limits)
        assert ok is False
        assert reason is not None
        assert "Memory" in reason
        assert "600.0" in reason

    def test_tokens_exceeded(self) -> None:
        limits = ResourceLimits(max_tokens=5000)
        usage: dict[str, Any] = {
            "cpu_seconds": 0, "peak_memory_mb": 0, "tokens_used": 9999, "cost_usd": 0
        }
        ok, reason = check_limits(usage, limits)
        assert ok is False
        assert reason is not None
        assert "Token" in reason
        assert "9999" in reason

    def test_cost_exceeded(self) -> None:
        limits = ResourceLimits(max_cost_usd=0.05)
        usage: dict[str, Any] = {
            "cpu_seconds": 0, "peak_memory_mb": 0, "tokens_used": 0, "cost_usd": 0.99
        }
        ok, reason = check_limits(usage, limits)
        assert ok is False
        assert reason is not None
        assert "Cost" in reason

    def test_exactly_at_limit_is_within(self) -> None:
        """Values exactly equal to the limit should still pass (not >)."""
        limits = ResourceLimits(max_cpu_seconds=10.0, max_memory_mb=512)
        usage: dict[str, Any] = {
            "cpu_seconds": 10.0,
            "peak_memory_mb": 512.0,
            "tokens_used": 100_000,
            "cost_usd": 0.10,
        }
        ok, _ = check_limits(usage, limits)
        assert ok is True

    def test_missing_keys_treated_as_zero(self) -> None:
        limits = ResourceLimits()
        ok, reason = check_limits({}, limits)
        assert ok is True
        assert reason is None

    def test_cpu_checked_first(self) -> None:
        """CPU violation should be reported before memory when both are exceeded."""
        limits = ResourceLimits(max_cpu_seconds=1.0, max_memory_mb=1)
        usage: dict[str, Any] = {
            "cpu_seconds": 100.0,
            "peak_memory_mb": 999.0,
            "tokens_used": 0,
            "cost_usd": 0,
        }
        ok, reason = check_limits(usage, limits)
        assert ok is False
        assert reason is not None
        assert "CPU" in reason  # CPU is checked first in the implementation

    def test_string_values_coerced(self) -> None:
        """check_limits casts values via float/int, so string numbers should work."""
        limits = ResourceLimits(max_cpu_seconds=10.0)
        usage: dict[str, Any] = {
            "cpu_seconds": "5.0",
            "peak_memory_mb": "100",
            "tokens_used": "500",
            "cost_usd": "0.01",
        }
        ok, reason = check_limits(usage, limits)
        assert ok is True
        assert reason is None

    @given(
        cpu=st.floats(
            min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False
        ),
        memory=st.floats(
            min_value=0.0, max_value=100_000.0, allow_nan=False, allow_infinity=False
        ),
        tokens=st.integers(min_value=0, max_value=10_000_000),
        cost=st.floats(
            min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False
        ),
    )
    @settings(max_examples=100)
    def test_returns_bool_and_optional_string(
        self, cpu: float, memory: float, tokens: int, cost: float
    ) -> None:
        limits = ResourceLimits(
            max_memory_mb=512,
            max_cpu_seconds=30.0,
            max_cost_usd=0.10,
            max_tokens=100_000,
        )
        usage: dict[str, Any] = {
            "cpu_seconds": cpu,
            "peak_memory_mb": memory,
            "tokens_used": tokens,
            "cost_usd": cost,
        }
        ok, reason = check_limits(usage, limits)
        assert isinstance(ok, bool)
        if ok:
            assert reason is None
        else:
            assert isinstance(reason, str)
            assert len(reason) > 0


# ---------------------------------------------------------------------------
# ResourceMonitor
# ---------------------------------------------------------------------------


class TestResourceMonitorLifecycle:
    def test_start_and_stop(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor.start(pid=None)
        assert monitor._thread is not None  # noqa: SLF001
        monitor.stop()
        assert monitor._thread is None  # noqa: SLF001

    def test_stop_before_start_is_safe(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor.stop()  # Should not raise

    def test_snapshot_before_start(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        snapshot = monitor.snapshot()
        assert "cpu_seconds" in snapshot
        assert "peak_memory_mb" in snapshot
        assert "tokens_used" in snapshot
        assert "cost_usd" in snapshot
        assert "elapsed_seconds" in snapshot

    def test_snapshot_initial_values(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        snapshot = monitor.snapshot()
        assert snapshot["tokens_used"] == 0
        assert snapshot["cost_usd"] == 0.0
        assert snapshot["peak_memory_mb"] == 0.0

    def test_elapsed_after_start(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor.start(pid=None)
        time.sleep(0.05)
        snapshot = monitor.snapshot()
        monitor.stop()
        assert snapshot["elapsed_seconds"] >= 0.0


class TestResourceMonitorMetricRecording:
    def test_record_tokens_accumulates(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor.record_tokens(100)
        monitor.record_tokens(250)
        snapshot = monitor.snapshot()
        assert snapshot["tokens_used"] == 350

    def test_record_cost_accumulates(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor.record_cost(0.01)
        monitor.record_cost(0.005)
        snapshot = monitor.snapshot()
        assert abs(snapshot["cost_usd"] - 0.015) < 1e-9

    def test_record_memory_updates_peak(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor.record_memory(100.0)
        monitor.record_memory(200.0)
        monitor.record_memory(150.0)  # Lower than peak — should not update
        snapshot = monitor.snapshot()
        assert snapshot["peak_memory_mb"] == 200.0

    def test_record_memory_does_not_decrease_peak(
        self, default_limits: ResourceLimits
    ) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor.record_memory(500.0)
        monitor.record_memory(50.0)
        assert monitor.snapshot()["peak_memory_mb"] == 500.0

    def test_thread_safe_token_recording(self, default_limits: ResourceLimits) -> None:
        """Concurrent token recording should not lose updates."""
        monitor = ResourceMonitor(default_limits)
        threads = [
            threading.Thread(target=lambda: monitor.record_tokens(1))
            for _ in range(100)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert monitor.snapshot()["tokens_used"] == 100


class TestResourceMonitorCheckLimits:
    def test_within_limits_initially(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        ok, reason = monitor.check_limits()
        assert ok is True
        assert reason is None

    def test_token_violation_detected(self) -> None:
        limits = ResourceLimits(max_tokens=10)
        monitor = ResourceMonitor(limits)
        monitor.record_tokens(100)
        ok, reason = monitor.check_limits()
        assert ok is False
        assert reason is not None

    def test_cost_violation_detected(self) -> None:
        limits = ResourceLimits(max_cost_usd=0.01)
        monitor = ResourceMonitor(limits)
        monitor.record_cost(1.0)
        ok, reason = monitor.check_limits()
        assert ok is False
        assert reason is not None

    def test_memory_violation_detected(self) -> None:
        limits = ResourceLimits(max_memory_mb=1)
        monitor = ResourceMonitor(limits)
        monitor.record_memory(999.0)
        ok, reason = monitor.check_limits()
        assert ok is False
        assert reason is not None


class TestResourceMonitorPsutilIntegration:
    def test_sample_with_no_pid_is_noop(self, default_limits: ResourceLimits) -> None:
        monitor = ResourceMonitor(default_limits)
        monitor._pid = None  # noqa: SLF001
        monitor._sample()  # Should not raise and should not change metrics
        assert monitor.snapshot()["peak_memory_mb"] == 0.0

    def test_sample_with_invalid_pid_does_not_raise(
        self, default_limits: ResourceLimits
    ) -> None:
        """Sampling a nonexistent PID should silently fail."""
        monitor = ResourceMonitor(default_limits)
        monitor._pid = 9999999  # noqa: SLF001  # Very unlikely to exist
        monitor._sample()  # Should not raise

    def test_sample_with_psutil_mocked(self, default_limits: ResourceLimits) -> None:
        """When psutil is available, _sample should update peak memory."""
        mock_psutil = MagicMock()
        mock_proc = MagicMock()
        mock_cpu = MagicMock()
        mock_cpu.user = 1.5
        mock_cpu.system = 0.5
        mock_mem = MagicMock()
        mock_mem.rss = 100 * 1024 * 1024  # 100 MiB in bytes
        mock_proc.cpu_times.return_value = mock_cpu
        mock_proc.memory_info.return_value = mock_mem
        mock_psutil.Process.return_value = mock_proc

        monitor = ResourceMonitor(default_limits)
        monitor._pid = 12345  # noqa: SLF001

        import aumai_sandbox.resources as resources_module
        original = resources_module._psutil_module  # noqa: SLF001
        resources_module._psutil_module = mock_psutil  # noqa: SLF001
        try:
            monitor._sample()
        finally:
            resources_module._psutil_module = original  # noqa: SLF001

        snapshot = monitor.snapshot()
        assert snapshot["peak_memory_mb"] == 100.0
        assert snapshot["cpu_seconds"] == 2.0
