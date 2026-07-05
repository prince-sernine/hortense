from __future__ import annotations

from hortense.entity_lifecycle import EntityLifecycleTracker, relay_fingerprint
from hortense.models import DetectionEvent


def _listener(
    *,
    event_id: str = "stealth_relay:listener:1",
    process_name: str = "weatherttracker.exe",
    process_path: str = r"C:\Apps\WeatherTracker\weatherttracker.exe",
    port: int = 8096,
    bind_scope: str = "all_interfaces",
    product_key: str = r"c:\apps\weathertracker",
) -> DetectionEvent:
    return DetectionEvent(
        id=event_id,
        severity="medium",
        category="stealth_relay",
        title="Suspicious TCP listener during interview session",
        detail="test",
        process_name=process_name,
        process_path=process_path,
        pid=4242,
        metadata={
            "signal": "listener",
            "local_port": port,
            "bind_scope": bind_scope,
            "product_key": product_key,
            "display_name": process_name,
        },
    )


def test_relay_fingerprint_uses_product_key() -> None:
    event = _listener()
    assert relay_fingerprint(event) == (
        r"c:\apps\weathertracker|relay|listener|8096|all_interfaces"
    )


def test_lifecycle_appeared_gone_returned_with_debounce() -> None:
    tracker = EntityLifecycleTracker()
    listener = _listener()

    appeared = tracker.update([listener], interview_active=True)
    assert len(appeared) == 1
    assert appeared[0].metadata["lifecycle"] == "appeared"

    first_miss = tracker.update([], interview_active=True)
    assert first_miss == []

    gone = tracker.update([], interview_active=True)
    gone_events = [e for e in gone if e.metadata.get("lifecycle") == "gone"]
    assert len(gone_events) == 1
    assert gone_events[0].metadata["lifecycle"] == "gone"

    returned = tracker.update([listener], interview_active=True)
    assert len(returned) == 1
    assert returned[0].metadata["lifecycle"] == "returned"


def test_lifecycle_flushes_gone_before_reset() -> None:
    tracker = EntityLifecycleTracker()
    listener = _listener()

    tracker.update([listener], interview_active=True)
    reset_events = tracker.update([], interview_active=False)
    gone_events = [e for e in reset_events if e.metadata.get("lifecycle") == "gone"]
    cleared_events = [e for e in reset_events if e.severity == "cleared"]
    assert gone_events
    assert cleared_events

    fresh = tracker.update([listener], interview_active=True)
    assert len(fresh) == 1
    assert fresh[0].metadata["lifecycle"] == "appeared"
