from __future__ import annotations

from pathlib import Path

from hortense.config import ScanConfig
from hortense.daemon import TUI_RECENT_EVENT_LIMIT, ScanDaemon
from hortense.models import DetectionEvent


def _static_process(event_id: str) -> DetectionEvent:
    return DetectionEvent(
        id=event_id,
        severity="high",
        category="process",
        title="Known interview-assist process (process name signature)",
        detail="Running process matched community signature: Cluely.exe",
        process_name="Cluely.exe",
        metadata={
            "product_key": r"c:\users\me\appdata\local\cluely",
            "match_reason": "process name signature",
        },
    )


def test_human_display_dedupe_uses_stable_static_key(tmp_path: Path) -> None:
    daemon = ScanDaemon(ScanConfig(jsonl_path=tmp_path / "events.jsonl", watch_dashboard=False))

    first = daemon._fresh_display_events([_static_process("process:1")])
    second = daemon._fresh_display_events([_static_process("process:2")])

    assert len(first) == 1
    assert second == []


def test_human_display_keeps_repeated_lifecycle_events(tmp_path: Path) -> None:
    daemon = ScanDaemon(ScanConfig(jsonl_path=tmp_path / "events.jsonl", watch_dashboard=False))
    first = DetectionEvent(
        id="lifecycle:gone:1:pk|process",
        severity="low",
        category="process",
        title="Process layer cleared - Cluely.exe",
        detail="test",
        process_name="Cluely.exe",
        metadata={"lifecycle": "gone"},
    )
    second = DetectionEvent(
        id="lifecycle:gone:2:pk|process",
        severity="low",
        category="process",
        title="Process layer cleared - Cluely.exe",
        detail="test",
        process_name="Cluely.exe",
        metadata={"lifecycle": "gone"},
    )

    assert daemon._fresh_display_events([first]) == [first]
    assert daemon._fresh_display_events([second]) == [second]


def test_tui_state_keeps_recent_100_display_events(tmp_path: Path) -> None:
    daemon = ScanDaemon(ScanConfig(jsonl_path=tmp_path / "events.jsonl", watch_dashboard=False))
    events = [
        DetectionEvent(
            id=f"lifecycle:appeared:{idx}:pk|process",
            severity="medium",
            category="process",
            title=f"Process appeared - Tool {idx}",
            detail="test",
            process_name=f"Tool{idx}.exe",
            metadata={"lifecycle": "appeared"},
        )
        for idx in range(TUI_RECENT_EVENT_LIMIT + 5)
    ]

    daemon._update_state([], events)

    assert len(daemon.state.events) == TUI_RECENT_EVENT_LIMIT
    assert daemon.state.events[0].id == "lifecycle:appeared:5:pk|process"
    assert daemon.state.events[-1].id == "lifecycle:appeared:104:pk|process"


def test_tui_state_snaps_to_live_only_when_new_display_events(tmp_path: Path) -> None:
    daemon = ScanDaemon(ScanConfig(jsonl_path=tmp_path / "events.jsonl", watch_dashboard=False))
    daemon.state.scroll_offset = 12

    daemon._update_state([], [])

    assert daemon.state.scroll_offset == 12

    event = DetectionEvent(
        id="lifecycle:appeared:1:pk|process",
        severity="medium",
        category="process",
        title="Process appeared - Tool",
        detail="test",
        process_name="Tool.exe",
        metadata={"lifecycle": "appeared"},
    )
    daemon._update_state([], [event])

    assert daemon.state.scroll_offset == 0


def test_tui_cap_does_not_affect_fresh_display_events(tmp_path: Path) -> None:
    daemon = ScanDaemon(ScanConfig(jsonl_path=tmp_path / "events.jsonl", watch_dashboard=False))
    events = [
        DetectionEvent(
            id=f"lifecycle:gone:{idx}:pk|process",
            severity="low",
            category="process",
            title=f"Process layer cleared - Tool {idx}",
            detail="test",
            process_name=f"Tool{idx}.exe",
            metadata={"lifecycle": "gone"},
        )
        for idx in range(TUI_RECENT_EVENT_LIMIT + 5)
    ]

    fresh = daemon._fresh_display_events(events)

    assert len(fresh) == len(events)
    assert {event.id for event in fresh} == {event.id for event in events}
