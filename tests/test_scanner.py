from __future__ import annotations

from hortense.models import DetectionEvent
from hortense.scanner import (
    _collapse_process_events,
    _collapse_window_events,
    _dedupe,
    correlate_by_product_key,
)


def _event(
    *,
    event_id: str,
    category: str,
    process_path: str | None = None,
    process_name: str | None = None,
    match_reason: str = "",
    product_key: str = "",
    pid: int | None = None,
) -> DetectionEvent:
    metadata: dict = {"match_reason": match_reason}
    if product_key:
        metadata["product_key"] = product_key
    return DetectionEvent(
        id=event_id,
        severity="high",
        category=category,
        title="test",
        detail="test",
        process_path=process_path,
        process_name=process_name,
        pid=pid,
        metadata=metadata,
    )


def test_dedupe_keeps_single_event_per_id() -> None:
    events = [
        _event(event_id="a", category="overlay", process_name="x.exe"),
        _event(event_id="a", category="overlay", process_name="x.exe"),
    ]
    assert len(_dedupe(events)) == 1


def test_collapse_window_events_merges_same_product_key_and_title() -> None:
    pk = r"c:\apps\cluely-v2"
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
            metadata={"product_key": pk},
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
            metadata={"product_key": pk},
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


def test_microphone_attribution_upgrades_on_shared_product_key() -> None:
    pk = r"c:\users\me\appdata\local\lynccontainer"
    events = [
        _event(
            event_id="display_affinity:hwnd:10",
            category="display_affinity",
            product_key=pk,
            pid=10,
        ),
        DetectionEvent(
            id="microphone:30:10",
            severity="medium",
            category="microphone",
            title="Microphone capture attributed to suspicious host",
            detail="Audio capture is owned by msedgewebview2.exe.",
            process_name="Lynccontainer.exe",
            process_path=r"C:\Users\me\AppData\Local\Lynccontainer\Lynccontainer.exe",
            pid=30,
            metadata={
                "product_key": pk,
                "attributed_pid": 10,
                "confidence": "medium",
            },
        ),
    ]

    correlated = correlate_by_product_key(events)
    mic = next(event for event in correlated if event.category == "microphone")

    assert mic.severity == "high"
    assert mic.metadata["confidence"] == "strong"
    assert mic.metadata["correlated_categories"] == ["display_affinity"]


def test_microphone_attribution_does_not_cross_product_clusters() -> None:
    events = [
        _event(
            event_id="display_affinity:hwnd:10",
            category="display_affinity",
            product_key=r"c:\apps\a",
            pid=10,
        ),
        DetectionEvent(
            id="microphone:40",
            severity="medium",
            category="microphone",
            title="Unattributed microphone capture during interview session",
            detail="SoundRecorder.exe",
            process_name="SoundRecorder.exe",
            pid=40,
            metadata={
                "product_key": r"c:\apps\b",
                "confidence": "heuristic",
            },
        ),
    ]

    correlated = correlate_by_product_key(events)
    mic = next(event for event in correlated if event.category == "microphone")

    assert mic.severity == "medium"
    assert mic.metadata["confidence"] == "heuristic"


def test_relay_correlation_upgrades_on_shared_product_key() -> None:
    pk = r"c:\apps\weathertracker"
    events = [
        _event(
            event_id="process:4242:weatherttracker.exe",
            category="process",
            process_path=r"C:\Apps\WeatherTracker\weatherttracker.exe",
            product_key=pk,
            pid=4242,
        ),
        DetectionEvent(
            id="stealth_relay:listener:4242:8096",
            severity="medium",
            category="stealth_relay",
            title="Suspicious TCP listener during interview session",
            detail="listening on 8096",
            process_name="weatherttracker.exe",
            process_path=r"C:\Apps\WeatherTracker\weatherttracker.exe",
            pid=4242,
            metadata={
                "product_key": pk,
                "signal": "listener",
                "local_port": 8096,
                "bind_scope": "all_interfaces",
            },
        ),
    ]

    correlated = correlate_by_product_key(events)
    relay = next(event for event in correlated if event.category == "stealth_relay")

    assert relay.severity == "high"
    assert relay.metadata["confidence"] == "strong"
    assert relay.metadata["correlated_categories"] == ["process"]
