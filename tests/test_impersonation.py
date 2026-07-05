from __future__ import annotations

from hortense.impersonation import impersonation_events, is_typosquat
from hortense.models import DetectionEvent


def test_typosquat_requires_min_length() -> None:
    assert not is_typosquat("Spotify.exe", "Spot.exe")
    assert is_typosquat("Spotifiy.exe", "Spotify.exe")


def test_impersonation_passthrough_when_catalog_empty() -> None:
    events = [
        DetectionEvent(
            id="process:1",
            severity="high",
            category="process",
            title="process",
            detail="detail",
            process_name="Cluely.exe",
        )
    ]
    assert impersonation_events(events, []) == events


def test_impersonation_escalates_mismatch_publisher() -> None:
    events = [
        DetectionEvent(
            id="process:1",
            severity="high",
            category="process",
            title="process",
            detail="detail",
            process_name="Spotifiy.exe",
            process_path=r"C:\Users\me\AppData\Local\Fake\Spotifiy.exe",
            metadata={"product_key": r"c:\users\me\appdata\local\fake", "publisher": "unknown"},
        )
    ]
    catalog = [{"name": "Spotify.exe", "publisher": "Spotify AB"}]
    out = impersonation_events(events, catalog)
    assert out[0].severity == "high"
    assert out[0].metadata.get("impersonation") is True
