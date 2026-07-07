from __future__ import annotations

from hortense.models import DetectionEvent
from hortense.scanner import (
    _collapse_process_events,
    _collapse_window_events,
    _dedupe,
    _native_meeting_processes,
    _surface_microphones,
    _surface_relays,
    apply_cluster_assessments,
    known_app_anomaly_events,
    _relay_process_rules,
    correlate_by_product_key,
)
from hortense.watch_state import meeting_app_names


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


def test_collapse_process_events_prefers_anchor_pid() -> None:
    pk = r"c:\apps\weathertracker"
    events = [
        _event(
            event_id="process:worker",
            category="process",
            process_path=r"C:\Apps\WeatherTracker\Weather Tracker.exe",
            process_name="Weather Tracker.exe",
            match_reason="process name signature",
            product_key=pk,
            pid=18940,
        ),
        _event(
            event_id="process:root",
            category="process",
            process_path=r"C:\Apps\WeatherTracker\Weather Tracker.exe",
            process_name="Weather Tracker.exe",
            match_reason="process name signature",
            product_key=pk,
            pid=4336,
        ),
    ]
    events[0] = DetectionEvent(
        **{**events[0].__dict__, "metadata": {**events[0].metadata, "anchor_pid": 4336}}
    )
    events[1] = DetectionEvent(
        **{**events[1].__dict__, "metadata": {**events[1].metadata, "anchor_pid": 4336}}
    )

    collapsed = _collapse_process_events(events)
    process_events = [event for event in collapsed if event.category == "process"]
    assert len(process_events) == 1
    assert process_events[0].pid == 4336


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


def test_microphone_on_modified_known_app_stays_medium() -> None:
    pk = r"c:\users\me\appdata\roaming\spotify"
    events = [
        _event(
            event_id="known_app_anomaly:spotify",
            category="known_app_anomaly",
            process_name="Spotify.exe",
            process_path=r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
            product_key=pk,
        ),
        DetectionEvent(
            id="microphone:spotify",
            severity="medium",
            category="microphone",
            title="Microphone capture in progress",
            detail="Spotify.exe is holding the capture device.",
            process_name="Spotify.exe",
            process_path=r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
            metadata={
                "product_key": pk,
                "confidence": "heuristic",
            },
        ),
    ]

    correlated = correlate_by_product_key(events)
    mic = next(event for event in correlated if event.category == "microphone")

    assert mic.severity == "medium"
    assert mic.title == "Microphone capture on modified app"
    assert mic.metadata["confidence"] == "corroborated"
    assert mic.metadata["correlated_categories"] == ["known_app_anomaly"]


def test_cluster_assessment_adds_meeting_context_and_classification() -> None:
    pk = r"c:\apps\parakeet"
    events = [
        _event(
            event_id="overlay:hwnd:10",
            category="overlay",
            process_name="Parakeet.exe",
            product_key=pk,
        ),
        DetectionEvent(
            id="microphone:parakeet",
            severity="high",
            category="microphone",
            title="Microphone capture attributed to suspicious product",
            detail="Parakeet.exe is holding the capture device.",
            process_name="Parakeet.exe",
            metadata={
                "product_key": pk,
                "confidence": "strong",
            },
        ),
    ]

    assessed = apply_cluster_assessments(events, meeting_context="pre_call")
    mic = next(event for event in assessed if event.category == "microphone")

    assert mic.metadata["meeting_context"] == "pre_call"
    assert mic.metadata["cluster_classification"] == "suspicious_stack"
    assert mic.metadata["cluster_confidence"] == "strong"
    assert mic.metadata["cluster_reasons"] == ["microphone", "overlay"]


def test_bare_microphone_is_quiet_pre_call_watch() -> None:
    mic = DetectionEvent(
        id="microphone:soundrecorder",
        severity="medium",
        category="microphone",
        title="Unattributed microphone capture by non-allowlisted process",
        detail="SoundRecorder.exe is holding the capture device.",
        process_name="SoundRecorder.exe",
        metadata={
            "product_key": r"c:\windows\soundrecorder",
            "confidence": "heuristic",
        },
    )

    assert _surface_microphones([mic], interview_active=False) == []
    assert _surface_microphones([mic], interview_active=True) == [mic]


def test_pre_call_microphone_surfaces_with_suspicious_sibling() -> None:
    pk = r"c:\apps\parakeet"
    overlay = _event(
        event_id="overlay:hwnd:10",
        category="overlay",
        product_key=pk,
    )
    mic = DetectionEvent(
        id="microphone:parakeet",
        severity="high",
        category="microphone",
        title="Microphone capture attributed to suspicious product",
        detail="Parakeet.exe is holding the capture device.",
        process_name="Parakeet.exe",
        metadata={
            "product_key": pk,
            "confidence": "strong",
        },
    )

    assert _surface_microphones([overlay, mic], interview_active=False) == [
        overlay,
        mic,
    ]


def test_pre_call_microphone_and_relay_surface_together() -> None:
    pk = r"c:\apps\parakeet"
    relay = _bare_relay(product_key=pk)
    mic = DetectionEvent(
        id="microphone:parakeet",
        severity="high",
        category="microphone",
        title="Microphone capture attributed to suspicious product",
        detail="Parakeet.exe is holding the capture device.",
        process_name="Parakeet.exe",
        metadata={
            "product_key": pk,
            "confidence": "strong",
        },
    )

    relays = _surface_relays([relay, mic], interview_active=False)
    assert relays == [relay, mic]
    assert _surface_microphones(relays, interview_active=False) == [relay, mic]


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


def test_relay_on_modified_app_is_informational_not_threat() -> None:
    # A relay on a modified known app with no cheat-shaped signals is informational.
    # An all-interfaces bind is a louder shape, so this one grades medium.
    pk = r"c:\users\me\appdata\roaming\spotify"
    events = [
        _event(
            event_id="known_app_anomaly:spotify",
            category="known_app_anomaly",
            process_name="Spotify.exe",
            process_path=r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
            product_key=pk,
        ),
        DetectionEvent(
            id="stealth_relay:listener:20:11245",
            severity="medium",
            category="stealth_relay",
            title="Suspicious TCP listener during interview session",
            detail="listening on 11245",
            process_name="Spotify.exe",
            process_path=r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
            pid=20,
            metadata={
                "product_key": pk,
                "signal": "listener",
                "local_port": 11245,
                "bind_scope": "all_interfaces",
            },
        ),
    ]

    correlated = correlate_by_product_key(events)
    relay = next(event for event in correlated if event.category == "stealth_relay")

    assert relay.severity == "medium"
    assert relay.title == "Open listener on modified app - Spotify.exe"
    assert relay.metadata["relay_tier"] == "anomaly_informational"
    assert relay.metadata["correlated_categories"] == ["known_app_anomaly"]


def test_loopback_relay_on_modified_app_grades_low() -> None:
    # No loud shape, and the anomaly is only unsigned (not a masquerade), so it
    # settles at low: informational, quiet.
    pk = r"c:\users\me\appdata\roaming\spotify"
    events = [
        _event(
            event_id="known_app_anomaly:spotify",
            category="known_app_anomaly",
            process_name="Spotify.exe",
            process_path=r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
            product_key=pk,
        ),
        DetectionEvent(
            id="stealth_relay:listener:20:11245",
            severity="medium",
            category="stealth_relay",
            title="Suspicious TCP listener during interview session",
            detail="listening on 11245",
            process_name="Spotify.exe",
            process_path=r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
            pid=20,
            metadata={
                "product_key": pk,
                "signal": "listener",
                "local_port": 11245,
                "bind_scope": "loopback",
            },
        ),
    ]

    correlated = correlate_by_product_key(events)
    relay = next(event for event in correlated if event.category == "stealth_relay")

    assert relay.severity == "low"
    assert relay.metadata["relay_tier"] == "anomaly_informational"


def _bare_relay(*, product_key: str, port: int = 8096) -> DetectionEvent:
    return DetectionEvent(
        id=f"stealth_relay:listener:{port}",
        severity="medium",
        category="stealth_relay",
        title="Suspicious TCP listener",
        detail=f"listening on {port}",
        process_name="thing.exe",
        pid=1,
        metadata={
            "product_key": product_key,
            "signal": "listener",
            "local_port": port,
            "bind_scope": "all_interfaces",
        },
    )


def test_surface_gate_drops_bare_relay_off_call() -> None:
    pk = r"c:\apps\thing"
    events = [_bare_relay(product_key=pk)]
    surfaced = _surface_relays(events, interview_active=False)
    assert surfaced == []


def test_surface_gate_keeps_bare_relay_during_call() -> None:
    pk = r"c:\apps\thing"
    events = [_bare_relay(product_key=pk)]
    surfaced = _surface_relays(events, interview_active=True)
    assert len(surfaced) == 1


def test_surface_gate_keeps_relay_on_anomaly_cluster_off_call() -> None:
    pk = r"c:\users\me\appdata\roaming\spotify"
    anomaly = _event(
        event_id="known_app_anomaly:spotify",
        category="known_app_anomaly",
        process_name="Spotify.exe",
        product_key=pk,
    )
    relay = _bare_relay(product_key=pk, port=11245)
    surfaced = _surface_relays([anomaly, relay], interview_active=False)

    categories = {e.category for e in surfaced}
    assert categories == {"known_app_anomaly", "stealth_relay"}


def test_surface_gate_keeps_relay_on_threat_cluster_off_call() -> None:
    pk = r"c:\apps\cluely"
    process = _event(
        event_id="process:cluely",
        category="process",
        process_name="Cluely.exe",
        product_key=pk,
    )
    relay = _bare_relay(product_key=pk, port=9999)
    surfaced = _surface_relays([process, relay], interview_active=False)

    assert any(e.category == "stealth_relay" for e in surfaced)


def test_relay_process_rules_expand_publishers_and_prefixes() -> None:
    rules = _relay_process_rules(
        [
            {
                "name": "Spotify.exe",
                "publishers": ["Spotify AB", "Spotify USA Inc"],
                "path_prefixes": [r"\appdata\roaming\spotify\\"],
            }
        ]
    )

    assert (
        "Spotify.exe\tSpotify AB\t\\appdata\\roaming\\spotify\\\\"
        in rules
    )
    assert len(rules) == 2


def test_meeting_app_names_uses_distinct_open_process_names() -> None:
    snapshot = [
        {"exe": "zoom.exe"},
        {"exe": "Zoom.exe"},
        {"exe": "chrome.exe"},
        {"exe": "notepad.exe"},
    ]

    names, raw = meeting_app_names(snapshot, ["zoom.exe", "chrome.exe"])
    assert names == ["Chrome", "Zoom"]
    assert raw == ["chrome.exe", "zoom.exe"]


def test_native_meeting_processes_excludes_browsers() -> None:
    assert _native_meeting_processes(
        ["zoom.exe", "chrome.exe", "msedge.exe", "teams.exe"]
    ) == ["zoom.exe", "teams.exe"]


def test_known_app_anomaly_flags_unsigned_catalog_app() -> None:
    events = known_app_anomaly_events(
        [
            {
                "pid": 10,
                "exe": "Spotify.exe",
                "path": r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
            }
        ],
        [
            {
                "name": "Spotify.exe",
                "publishers": ["Spotify AB"],
                "path_prefixes": [r"\appdata\roaming\spotify\\"],
            }
        ],
        suspicious_path_prefixes=[r"\appdata\roaming\\"],
        signer_lookup=lambda _path: {
            "signed": False,
            "signature_valid": False,
            "publisher": None,
        },
    )

    assert len(events) == 1
    assert events[0].category == "known_app_anomaly"
    assert "modified or unofficial build" in events[0].detail


def test_known_app_anomaly_is_catalog_general() -> None:
    events = known_app_anomaly_events(
        [
            {
                "pid": 20,
                "exe": "WhatsApp.exe",
                "path": r"C:\Users\me\AppData\Local\WhatsApp\WhatsApp.exe",
            }
        ],
        [
            {
                "name": "WhatsApp.exe",
                "publisher": "WhatsApp LLC",
                "path_prefixes": [r"\appdata\local\whatsapp\\"],
            }
        ],
        suspicious_path_prefixes=[],
        signer_lookup=lambda _path: {
            "signed": True,
            "signature_valid": True,
            "publisher": "Unexpected Publisher",
        },
    )

    assert len(events) == 1
    assert events[0].process_name == "WhatsApp.exe"
    assert "wrong publisher" in events[0].metadata["anomaly_reasons"]
