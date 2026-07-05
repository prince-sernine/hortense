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
