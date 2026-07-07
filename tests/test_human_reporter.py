from __future__ import annotations

import io

from hortense.human_reporter import HumanReporter
from hortense.models import DetectionEvent


def test_human_reporter_emits_severity_and_detail_without_color() -> None:
    stream = io.StringIO()
    reporter = HumanReporter(stream=stream, use_color=False)
    reporter.emit(
        DetectionEvent(
            id="test:1",
            severity="high",
            category="stealth_relay",
            title="Suspicious stealth relay correlated with interview-assist evidence",
            detail="listener on port 8096",
            process_name="weatherttracker.exe",
            pid=4242,
        )
    )
    output = stream.getvalue()
    assert "[HIGH]" in output
    assert "listener on port 8096" in output
    assert "weatherttracker.exe" in output


def test_human_reporter_humanizes_still_active_fingerprints() -> None:
    stream = io.StringIO()
    reporter = HumanReporter(stream=stream, use_color=False)
    reporter.emit(
        DetectionEvent(
            id="lifecycle:gone:1",
            severity="low",
            category="stealth_relay",
            title="Relay layer cleared",
            detail="test",
            metadata={
                "still_active": [
                    r"c:\apps\tool|relay|listener|8096|all_interfaces",
                    r"c:\apps\tool|microphone",
                ]
            },
        )
    )

    output = stream.getvalue()
    assert "still active: relay listener, microphone" in output
    assert "8096" not in output


def test_human_reporter_uses_display_alias_for_obfuscated_process() -> None:
    stream = io.StringIO()
    reporter = HumanReporter(stream=stream, use_color=False)
    raw = "\u2800.exe"
    display = "parakeetai-desktop [U+2800].exe"
    reporter.emit(
        DetectionEvent(
            id="process:1",
            severity="high",
            category="process",
            title=f"Process appeared - {display}",
            detail=f"Running process matched community signature: {raw}",
            process_name=raw,
            pid=11012,
            metadata={
                "display_name": display,
                "raw_process_name": raw,
                "obfuscated_executable": True,
            },
        )
    )
    output = stream.getvalue()
    assert display in output
    assert "process: parakeetai-desktop [U+2800].exe (pid=11012)" in output
    assert raw not in output


def test_human_reporter_formats_multi_pid_rollup() -> None:
    stream = io.StringIO()
    reporter = HumanReporter(stream=stream, use_color=False)
    reporter.emit(
        DetectionEvent(
            id="product:cleared:1",
            severity="cleared",
            category="product_session",
            title="Session ended - Weather Tracker.exe (all signals cleared)",
            detail="All corroborating signals for this product cluster have cleared.",
            process_name="Weather Tracker.exe",
            metadata={
                "display_name": "Weather Tracker.exe",
                "pids_cleared": [18936, 15960],
            },
        )
    )
    output = stream.getvalue()
    assert "process: Weather Tracker.exe (pids=18936, 15960)" in output
