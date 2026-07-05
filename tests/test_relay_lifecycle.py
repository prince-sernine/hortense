from __future__ import annotations

from hortense.models import DetectionEvent
from hortense.relay_lifecycle import RelayLifecycleTracker, relay_fingerprint


def _listener(
    *,
    event_id: str = "stealth_relay:listener:1",
    process_name: str = "weatherttracker.exe",
    process_path: str = r"C:\Apps\WeatherTracker\weatherttracker.exe",
    port: int = 8096,
    bind_scope: str = "all_interfaces",
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
        },
    )


def test_relay_fingerprint_is_stable() -> None:
    event = _listener()
    assert relay_fingerprint(event) == (
        "weatherttracker.exe|8096|all_interfaces|"
        r"c:\apps\weathertracker\weatherttracker.exe"
    )


def test_lifecycle_appeared_gone_returned() -> None:
    tracker = RelayLifecycleTracker()
    listener = _listener()

    appeared = tracker.update([listener], interview_active=True)
    assert len(appeared) == 1
    assert appeared[0].metadata["lifecycle"] == "appeared"

    quiet = tracker.update([], interview_active=True)
    assert len(quiet) == 1
    assert quiet[0].metadata["lifecycle"] == "gone"

    returned = tracker.update([listener], interview_active=True)
    assert len(returned) == 1
    assert returned[0].metadata["lifecycle"] == "returned"


def test_lifecycle_resets_when_interview_inactive() -> None:
    tracker = RelayLifecycleTracker()
    listener = _listener()

    tracker.update([listener], interview_active=True)
    reset = tracker.update([listener], interview_active=False)
    assert reset == []

    fresh = tracker.update([listener], interview_active=True)
    assert len(fresh) == 1
    assert fresh[0].metadata["lifecycle"] == "appeared"
