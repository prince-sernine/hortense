from __future__ import annotations

from hortense.models import DetectionEvent
from hortense.scanner import (
    _collapse_process_events,
    _collapse_window_events,
    _correlate_microphone_attribution,
    _dedupe,
)


def _event(
    *,
    event_id: str,
    category: str,
    process_path: str | None = None,
    process_name: str | None = None,
    match_reason: str = "",
) -> DetectionEvent:
    return DetectionEvent(
        id=event_id,
        severity="high",
        category=category,
        title="test",
        detail="test",
        process_path=process_path,
        process_name=process_name,
        metadata={"match_reason": match_reason},
    )


def test_dedupe_keeps_single_event_per_id() -> None:
    events = [
        _event(event_id="a", category="overlay", process_name="x.exe"),
        _event(event_id="a", category="overlay", process_name="x.exe"),
    ]
    assert len(_dedupe(events)) == 1


def test_collapse_window_events_merges_same_pid_and_title() -> None:
    events = [
        DetectionEvent(
            id="display_affinity:hwnd1:12376",
            severity="high",
            category="display_affinity",
            title="Window excluded from screen capture (WDA_EXCLUDEFROMCAPTURE)",
            detail="first hwnd",
            process_name="Cluely.exe",
            process_path=r"C:\Apps\cluely-v2\Cluely.exe",
            pid=12376,
            hwnd=1,
            window_title="Cluely",
        ),
        DetectionEvent(
            id="display_affinity:hwnd2:12376",
            severity="high",
            category="display_affinity",
            title="Window excluded from screen capture (WDA_EXCLUDEFROMCAPTURE)",
            detail="second hwnd",
            process_name="Cluely.exe",
            process_path=r"C:\Apps\cluely-v2\Cluely.exe",
            pid=12376,
            hwnd=2,
            window_title="Cluely",
        ),
    ]

    collapsed = _collapse_window_events(events)
    assert len(collapsed) == 1


def test_collapse_process_events_merges_same_install_path() -> None:
    events = [
        _event(
            event_id="process:1:cluely.exe",
            category="process",
            process_path=r"C:\Apps\cluely-v2\Cluely.exe",
            match_reason="process name signature",
        ),
        _event(
            event_id="process:2:cluely.exe",
            category="process",
            process_path=r"C:\Apps\cluely-v2\Cluely.exe",
            match_reason="process name signature",
        ),
        _event(
            event_id="overlay:1",
            category="overlay",
        ),
    ]

    collapsed = _collapse_process_events(events)
    process_events = [event for event in collapsed if event.category == "process"]
    overlay_events = [event for event in collapsed if event.category == "overlay"]

    assert len(process_events) == 1
    assert len(overlay_events) == 1


def test_microphone_attribution_upgrades_when_same_host_has_window_evidence() -> None:
    events = [
        DetectionEvent(
            id="display_affinity:hwnd:10",
            severity="high",
            category="display_affinity",
            title="Window excluded from screen capture",
            detail="hidden window",
            process_name="Lynccontainer.exe",
            process_path=r"C:\Users\me\AppData\Local\Lynccontainer\Lynccontainer.exe",
            pid=10,
        ),
        DetectionEvent(
            id="microphone:30:10",
            severity="medium",
            category="microphone",
            title="Microphone capture attributed to suspicious host",
            detail="Audio capture is owned by msedgewebview2.exe, but its process tree points to Lynccontainer.exe.",
            process_name="Lynccontainer.exe",
            process_path=r"C:\Users\me\AppData\Local\Lynccontainer\Lynccontainer.exe",
            pid=30,
            metadata={
                "audio_owner_pid": 30,
                "audio_owner_process_name": "msedgewebview2.exe",
                "attributed_pid": 10,
                "confidence": "medium",
            },
        ),
    ]

    correlated = _correlate_microphone_attribution(events)
    mic = next(event for event in correlated if event.category == "microphone")

    assert mic.severity == "high"
    assert mic.metadata["confidence"] == "strong"
    assert mic.metadata["correlated_categories"] == ["display_affinity"]


def test_microphone_attribution_does_not_cross_process_trees() -> None:
    events = [
        DetectionEvent(
            id="display_affinity:hwnd:10",
            severity="high",
            category="display_affinity",
            title="Window excluded from screen capture",
            detail="hidden window",
            process_name="Lynccontainer.exe",
            pid=10,
        ),
        DetectionEvent(
            id="microphone:40",
            severity="medium",
            category="microphone",
            title="Unattributed microphone capture during interview session",
            detail="Non-allowlisted process holds an active audio capture session: SoundRecorder.exe",
            process_name="SoundRecorder.exe",
            pid=40,
            metadata={
                "audio_owner_pid": 40,
                "audio_owner_process_name": "SoundRecorder.exe",
                "confidence": "heuristic",
            },
        ),
    ]

    correlated = _correlate_microphone_attribution(events)
    mic = next(event for event in correlated if event.category == "microphone")

    assert mic.severity == "medium"
    assert mic.metadata["confidence"] == "heuristic"
