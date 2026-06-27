from __future__ import annotations

import json

from hortense.models import DetectionEvent


def test_detection_event_from_raw_parses_metadata_json_string() -> None:
    raw = {
        "id": "process:1:test",
        "severity": "high",
        "category": "process",
        "title": "t",
        "detail": "d",
        "metadata": json.dumps({"match_reason": "process name signature"}),
    }
    event = DetectionEvent.from_raw(raw)
    assert event.metadata["match_reason"] == "process name signature"


def test_severity_score_ordering() -> None:
    high = DetectionEvent("a", "high", "x", "t", "d")
    low = DetectionEvent("b", "low", "x", "t", "d")
    assert high.score > low.score
