from __future__ import annotations

from dataclasses import replace

from hortense.entity_lifecycle import (
    EntityLifecycleTracker,
    format_signal_label,
    relay_fingerprint,
    signal_fingerprint,
)
from hortense.entity import format_process_identity
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


def _process() -> DetectionEvent:
    return DetectionEvent(
        id="process:cluely",
        severity="high",
        category="process",
        title="Known interview-assist process (process name signature)",
        detail="Running process matched community signature: Cluely.exe",
        process_name="Cluely.exe",
        process_path=r"C:\Users\me\AppData\Local\Cluely\Cluely.exe",
        metadata={
            "product_key": r"c:\users\me\appdata\local\cluely",
            "display_name": "Cluely.exe",
        },
    )


def _overlay(
    *,
    product_key: str = r"c:\users\me\appdata\local\cluely",
    process_name: str = "Cluely.Helper.exe",
    pid: int = 300,
) -> DetectionEvent:
    return DetectionEvent(
        id=f"overlay:{pid}",
        severity="medium",
        category="overlay",
        title="Suspicious overlay-style window",
        detail="Layered, topmost/click-through window covering meaningful screen area.",
        process_name=process_name,
        process_path=rf"C:\Users\me\AppData\Local\Cluely\{process_name}",
        pid=pid,
        window_title="Cluely",
        metadata={
            "product_key": product_key,
            "display_name": process_name,
        },
    )


def _display_affinity(
    *,
    product_key: str = r"c:\users\me\appdata\local\cluely",
    process_name: str = "Cluely.exe",
    pid: int = 200,
) -> DetectionEvent:
    return DetectionEvent(
        id=f"display_affinity:{pid}",
        severity="high",
        category="display_affinity",
        title="Window excluded from screen capture (WDA_EXCLUDEFROMCAPTURE)",
        detail="A visible top-level window uses display affinity WDA_EXCLUDEFROMCAPTURE.",
        process_name=process_name,
        process_path=rf"C:\Users\me\AppData\Local\Cluely\{process_name}",
        pid=pid,
        window_title="Cluely",
        metadata={
            "product_key": product_key,
            "display_name": process_name,
        },
    )


def _known_app_anomaly() -> DetectionEvent:
    return DetectionEvent(
        id="known_app_anomaly:spotify",
        severity="medium",
        category="known_app_anomaly",
        title="Known app integrity anomaly - Spotify.exe",
        detail="Spotify.exe looks modified.",
        process_name="Spotify.exe",
        process_path=r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe",
        metadata={
            "product_key": r"c:\users\me\appdata\roaming\spotify",
            "display_name": "Spotify.exe",
            "anomaly_reasons": ["unsigned", "publisher unknown"],
        },
    )


def _microphone(
    *,
    product_key: str = r"c:\users\me\appdata\roaming\spotify",
    process_name: str = "Spotify.exe",
) -> DetectionEvent:
    return DetectionEvent(
        id="microphone:capture",
        severity="medium",
        category="microphone",
        title="Microphone capture in progress",
        detail="A process is holding the capture device.",
        process_name=process_name,
        metadata={
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


def test_bare_listener_pauses_quietly_when_call_ends() -> None:
    tracker = EntityLifecycleTracker()
    listener = _listener()

    appeared = tracker.update([listener], interview_active=True)
    assert appeared[0].metadata["lifecycle"] == "appeared"

    # A bare, call-context relay pauses when the call ends. It must not fake a
    # gone or a cleared: the port never actually stopped, the meeting just closed.
    paused = tracker.update([], interview_active=False)
    assert [e for e in paused if e.metadata.get("lifecycle") == "gone"] == []
    assert [e for e in paused if e.severity == "cleared"] == []

    still_quiet = tracker.update([], interview_active=False)
    assert [e for e in still_quiet if e.metadata.get("lifecycle") == "gone"] == []
    assert [e for e in still_quiet if e.severity == "cleared"] == []

    # It can silently resurface on the next call as a fresh appearance.
    resumed = tracker.update([listener], interview_active=True)
    assert len(resumed) == 1
    assert resumed[0].metadata["lifecycle"] == "appeared"


def test_bare_microphone_pauses_quietly_when_call_ends() -> None:
    tracker = EntityLifecycleTracker()
    mic = _microphone()

    appeared = tracker.update([mic], interview_active=True)
    assert appeared[0].metadata["lifecycle"] == "appeared"

    paused = tracker.update([], interview_active=False)
    assert [e for e in paused if e.metadata.get("lifecycle") == "gone"] == []
    assert [e for e in paused if e.severity == "cleared"] == []

    still_quiet = tracker.update([], interview_active=False)
    assert [e for e in still_quiet if e.metadata.get("lifecycle") == "gone"] == []
    assert [e for e in still_quiet if e.severity == "cleared"] == []


def test_pre_call_microphone_with_retained_sibling_clears_normally() -> None:
    tracker = EntityLifecycleTracker()
    process = _process()
    mic = _microphone(product_key=r"c:\users\me\appdata\local\cluely")

    appeared = tracker.update([process, mic], interview_active=False)
    assert len([e for e in appeared if e.metadata.get("lifecycle") == "appeared"]) == 2

    first_miss = tracker.update([process], interview_active=False)
    assert [e for e in first_miss if e.metadata.get("lifecycle") == "gone"] == []

    gone = tracker.update([process], interview_active=False)
    gone_events = [e for e in gone if e.metadata.get("lifecycle") == "gone"]
    assert len(gone_events) == 1
    assert gone_events[0].category == "microphone"
    assert gone_events[0].metadata["lifecycle_scope"] == "partial"


def test_pre_call_microphone_and_relay_retain_each_other() -> None:
    pk = r"c:\apps\weathertracker"
    tracker = EntityLifecycleTracker()
    relay = _listener(product_key=pk)
    mic = _microphone(product_key=pk, process_name="WeatherTracker.exe")

    appeared = tracker.update([relay, mic], interview_active=False)
    assert len([e for e in appeared if e.metadata.get("lifecycle") == "appeared"]) == 2

    tracker.update([relay], interview_active=False)
    gone = tracker.update([relay], interview_active=False)
    gone_events = [e for e in gone if e.metadata.get("lifecycle") == "gone"]

    assert len(gone_events) == 1
    assert gone_events[0].category == "microphone"
    assert gone_events[0].metadata["lifecycle_scope"] == "partial"


def test_pre_call_local_process_lifecycle_repeats_with_unique_ids() -> None:
    tracker = EntityLifecycleTracker()
    process = _process()

    appeared = tracker.update([process], interview_active=False)
    assert appeared[0].metadata["lifecycle"] == "appeared"

    tracker.update([], interview_active=False)
    first_close = tracker.update([], interview_active=False)
    first_gone = next(e for e in first_close if e.metadata.get("lifecycle") == "gone")
    first_cleared = next(e for e in first_close if e.severity == "cleared")

    returned = tracker.update([process], interview_active=False)
    assert returned[0].metadata["lifecycle"] == "returned"

    tracker.update([], interview_active=False)
    second_close = tracker.update([], interview_active=False)
    second_gone = next(e for e in second_close if e.metadata.get("lifecycle") == "gone")
    second_cleared = next(e for e in second_close if e.severity == "cleared")

    assert first_gone.id != second_gone.id
    assert first_cleared.id != second_cleared.id


def test_known_app_anomaly_has_stable_lifecycle_fingerprint() -> None:
    assert signal_fingerprint(_known_app_anomaly()) == (
        r"c:\users\me\appdata\roaming\spotify|known_app_anomaly|"
        "unsigned,publisher unknown"
    )


def test_same_poll_full_clear_removes_stale_still_active_metadata() -> None:
    tracker = EntityLifecycleTracker()
    signals = [_process(), _display_affinity(), _overlay()]
    tracker.update(signals, interview_active=False)
    tracker.update([], interview_active=False)

    cleared = tracker.update([], interview_active=False)
    gone_events = [event for event in cleared if event.metadata.get("lifecycle") == "gone"]
    rollups = [event for event in cleared if event.metadata.get("lifecycle") == "cleared"]

    assert len(gone_events) == 3
    assert len(rollups) == 1
    assert all("still_active" not in event.metadata for event in gone_events)
    assert all("active_count" not in event.metadata for event in gone_events)
    assert all(
        event.metadata["lifecycle_scope"] == "cluster_clearing"
        for event in gone_events
    )
    assert all("signal_fingerprint" in event.metadata for event in gone_events)
    assert all("signal_cleared" in event.metadata for event in gone_events)


def test_partial_clear_keeps_still_active_metadata() -> None:
    tracker = EntityLifecycleTracker()
    process = _process()
    overlay = _overlay()
    tracker.update([process, overlay], interview_active=False)
    tracker.update([process], interview_active=False)

    cleared = tracker.update([process], interview_active=False)
    gone = next(event for event in cleared if event.metadata.get("lifecycle") == "gone")

    assert gone.metadata["lifecycle_scope"] == "partial"
    assert "still_active" in gone.metadata
    assert gone.metadata["active_count"] == 1


def test_full_clear_cleanup_uses_product_key_not_process_identity() -> None:
    tracker = EntityLifecycleTracker()
    product_key = r"c:\users\me\appdata\local\cluely"
    signals = [
        _display_affinity(product_key=product_key, process_name="Cluely.exe", pid=200),
        _overlay(product_key=product_key, process_name="Cluely.Helper.exe", pid=300),
    ]
    tracker.update(signals, interview_active=False)
    tracker.update([], interview_active=False)

    cleared = tracker.update([], interview_active=False)
    gone_events = [event for event in cleared if event.metadata.get("lifecycle") == "gone"]

    assert len(gone_events) == 2
    assert {event.process_name for event in gone_events} == {
        "Cluely.exe",
        "Cluely.Helper.exe",
    }
    assert all("still_active" not in event.metadata for event in gone_events)


def test_full_clear_cleanup_does_not_cross_products() -> None:
    tracker = EntityLifecycleTracker()
    product_a = _process()
    product_b_process = DetectionEvent(
        id="process:other",
        severity="high",
        category="process",
        title="Known interview-assist process (process name signature)",
        detail="Running process matched community signature: Other.exe",
        process_name="Other.exe",
        process_path=r"C:\Users\me\AppData\Local\Other\Other.exe",
        metadata={
            "product_key": r"c:\users\me\appdata\local\other",
            "display_name": "Other.exe",
        },
    )
    product_b_overlay = _overlay(
        product_key=r"c:\users\me\appdata\local\other",
        process_name="Other.Helper.exe",
        pid=500,
    )
    tracker.update([product_a, product_b_process, product_b_overlay], interview_active=False)
    tracker.update([product_b_process], interview_active=False)

    events = tracker.update([product_b_process], interview_active=False)
    product_a_gone = [
        event
        for event in events
        if event.metadata.get("product_key") == r"c:\users\me\appdata\local\cluely"
        and event.metadata.get("lifecycle") == "gone"
    ]
    product_b_gone = [
        event
        for event in events
        if event.metadata.get("product_key") == r"c:\users\me\appdata\local\other"
        and event.metadata.get("lifecycle") == "gone"
    ]

    assert product_a_gone
    assert all("still_active" not in event.metadata for event in product_a_gone)
    assert product_b_gone
    assert product_b_gone[0].metadata["lifecycle_scope"] == "partial"
    assert "still_active" in product_b_gone[0].metadata


def test_active_snapshot_keeps_debounced_missing_signal() -> None:
    tracker = EntityLifecycleTracker()
    listener = _listener()

    tracker.update([listener], interview_active=True)
    tracker.update([], interview_active=True)

    snapshot = tracker.active_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0].display_name == "weatherttracker.exe"
    assert snapshot[0].signals == ["relay listener"]
    assert snapshot[0].signal_count == 1


def test_anomaly_relay_stays_active_across_call_close() -> None:
    # SpotX-style: a modified app with an open relay. The call ends but the app
    # keeps running, so the surface gate keeps feeding both signals. Nothing must
    # clear, because nothing actually stopped.
    tracker = EntityLifecycleTracker()
    pk = r"c:\users\me\appdata\roaming\spotify"
    anomaly = _known_app_anomaly()
    relay = _listener(process_name="Spotify.exe", product_key=pk)

    tracker.update([anomaly, relay], interview_active=True)
    off_call = tracker.update([anomaly, relay], interview_active=False)

    assert [e for e in off_call if e.metadata.get("lifecycle") == "gone"] == []
    assert [e for e in off_call if e.severity == "cleared"] == []


def test_retained_relay_clears_when_port_stops_off_call() -> None:
    # Same cluster, but now the relay port actually stops while the app keeps
    # running and no call is active. That is a real stop and must clear, while the
    # anomaly persists (no full product clear).
    tracker = EntityLifecycleTracker()
    pk = r"c:\users\me\appdata\roaming\spotify"
    anomaly = _known_app_anomaly()
    relay = _listener(process_name="Spotify.exe", product_key=pk)

    tracker.update([anomaly, relay], interview_active=False)
    tracker.update([anomaly], interview_active=False)
    events = tracker.update([anomaly], interview_active=False)

    gone = [e for e in events if e.metadata.get("lifecycle") == "gone"]
    assert len(gone) == 1
    assert gone[0].metadata["signal_fingerprint"].endswith("all_interfaces")
    assert [e for e in events if e.severity == "cleared"] == []


def test_anomaly_and_relay_clear_together_when_app_closes_off_call() -> None:
    # The modified app closes entirely with no call active. Both signals vanish in
    # the same poll; the relay must still clear as a real stop (not pause), so the
    # cluster emits an honest session-ended clear.
    tracker = EntityLifecycleTracker()
    pk = r"c:\users\me\appdata\roaming\spotify"
    anomaly = _known_app_anomaly()
    relay = _listener(process_name="Spotify.exe", product_key=pk)

    tracker.update([anomaly, relay], interview_active=False)
    tracker.update([], interview_active=False)
    events = tracker.update([], interview_active=False)

    gone = [e for e in events if e.metadata.get("lifecycle") == "gone"]
    cleared = [e for e in events if e.severity == "cleared"]
    assert len(gone) == 2
    assert len(cleared) == 1


def test_bare_microphone_pauses_when_call_ends() -> None:
    tracker = EntityLifecycleTracker()
    mic = _microphone()

    tracker.update([mic], interview_active=True)
    paused = tracker.update([], interview_active=False)

    assert [e for e in paused if e.metadata.get("lifecycle") == "gone"] == []
    assert [e for e in paused if e.severity == "cleared"] == []


def test_appeared_inherits_signal_severity() -> None:
    # appeared/returned must carry the underlying signal's severity so the relay
    # tiers read honestly. A high signal reads high, a medium one reads medium.
    tracker = EntityLifecycleTracker()
    events = tracker.update([_process(), _overlay()], interview_active=False)
    severity_by_category = {
        e.category: e.severity
        for e in events
        if e.metadata.get("lifecycle") == "appeared"
    }

    assert severity_by_category["process"] == "high"
    assert severity_by_category["overlay"] == "medium"


def test_format_signal_label_hides_raw_fingerprint() -> None:
    assert (
        format_signal_label(r"c:\apps\weathertracker|relay|listener|8096|all_interfaces")
        == "relay listener"
    )
    assert format_signal_label(r"c:\apps\tool|display_affinity|main") == "display affinity"


def test_cleared_rollup_carries_session_pids_from_all_signals() -> None:
    pk = r"c:\apps\weathertracker"
    tracker = EntityLifecycleTracker()
    relay = _listener(product_key=pk, port=8096)
    relay = DetectionEvent(
        id=relay.id,
        severity=relay.severity,
        category=relay.category,
        title=relay.title,
        detail=relay.detail,
        process_name=relay.process_name,
        process_path=relay.process_path,
        pid=18936,
        metadata=dict(relay.metadata),
    )
    process = DetectionEvent(
        id="process:wt",
        severity="high",
        category="process",
        title="Known interview-assist process",
        detail="matched",
        process_name="Weather Tracker.exe",
        process_path=r"C:\Apps\WeatherTracker\Weather Tracker.exe",
        pid=15960,
        metadata={
            "product_key": pk,
            "display_name": "Weather Tracker.exe",
        },
    )
    tracker.update([relay, process], interview_active=True)
    tracker.update([], interview_active=True)
    events = tracker.update([], interview_active=True)
    cleared = next(e for e in events if e.severity == "cleared")
    assert cleared.metadata["pids_cleared"] == [15960, 18936]
    assert cleared.pid is None


def test_single_pid_cleared_rollup_sets_pid_field() -> None:
    tracker = EntityLifecycleTracker()
    process = _process()
    process = DetectionEvent(
        id=process.id,
        severity=process.severity,
        category=process.category,
        title=process.title,
        detail=process.detail,
        process_name=process.process_name,
        process_path=process.process_path,
        pid=11012,
        metadata=dict(process.metadata),
    )
    tracker.update([process], interview_active=False)
    tracker.update([], interview_active=False)
    events = tracker.update([], interview_active=False)
    cleared = next(e for e in events if e.severity == "cleared")
    assert cleared.pid == 11012
    assert cleared.metadata["pids_cleared"] == [11012]


def test_one_cleared_per_single_close_cycle() -> None:
    tracker = EntityLifecycleTracker()
    process = _process()
    tracker.update([process], interview_active=False)
    tracker.update([], interview_active=False)
    events = tracker.update([], interview_active=False)
    rollups = [e for e in events if e.severity == "cleared"]
    assert len(rollups) == 1


def test_one_poll_overlay_miss_does_not_spurious_returned() -> None:
    tracker = EntityLifecycleTracker()
    overlay = _overlay(pid=5568)

    tracker.update([overlay], interview_active=False)
    tracker.update([], interview_active=False)
    tracker.update([], interview_active=False)
    returned = tracker.update([overlay], interview_active=False)
    assert any(e.metadata.get("lifecycle") == "returned" for e in returned)

    tracker.update([], interview_active=False)

    back = tracker.update([overlay], interview_active=False)
    assert not any(e.metadata.get("lifecycle") == "returned" for e in back)


def test_overlay_holdover_injects_missing_overlay_for_one_poll() -> None:
    tracker = EntityLifecycleTracker()
    overlay = _overlay(pid=5568)
    live_pids = {5568}

    seeded = tracker.merge_overlay_holdover([overlay], live_pids=live_pids)
    tracker.update(seeded, interview_active=False)

    merged = tracker.merge_overlay_holdover([], live_pids=live_pids)
    assert len(merged) == 1
    tracker.update(merged, interview_active=False)

    merged_again = tracker.merge_overlay_holdover([], live_pids=live_pids)
    assert len(merged_again) == 1

    tracker.update(merged_again, interview_active=False)
    expired = tracker.merge_overlay_holdover([], live_pids=live_pids)
    assert expired == []


def test_overlay_holdover_invalidates_when_pid_dead() -> None:
    tracker = EntityLifecycleTracker()
    overlay = _overlay(pid=5568)

    seeded = tracker.merge_overlay_holdover([overlay], live_pids={5568})
    tracker.update(seeded, interview_active=False)
    merged = tracker.merge_overlay_holdover([], live_pids={5568})
    assert len(merged) == 1

    assert tracker.merge_overlay_holdover([], live_pids=set()) == []


def test_window_title_churn_same_hwnd_does_not_clear_or_return() -> None:
    tracker = EntityLifecycleTracker()
    overlay = replace(_overlay(pid=1560), hwnd=526222, window_title="parakeetai-desktop")
    affinity = replace(_display_affinity(pid=1560), hwnd=526222, window_title="parakeetai-desktop")
    renamed_overlay = replace(overlay, window_title="pmodule")
    renamed_affinity = replace(affinity, window_title="pmodule")

    appeared = tracker.update([overlay, affinity], interview_active=False)
    assert {event.metadata["lifecycle"] for event in appeared} == {"appeared"}

    churn = tracker.update([renamed_overlay, renamed_affinity], interview_active=False)
    assert not any(
        event.metadata.get("lifecycle") in {"gone", "returned", "appeared"}
        for event in churn
    )


def test_window_signals_with_different_hwnds_remain_separate() -> None:
    tracker = EntityLifecycleTracker()
    first = replace(_overlay(pid=1560), hwnd=111, window_title="parakeetai-desktop")
    second = replace(_overlay(pid=1560), hwnd=222, window_title="pmodule")

    appeared = tracker.update([first, second], interview_active=False)
    assert len([e for e in appeared if e.metadata.get("lifecycle") == "appeared"]) == 2

    tracker.update([second], interview_active=False)
    gone = tracker.update([second], interview_active=False)
    cleared = [event for event in gone if event.metadata.get("lifecycle") == "gone"]

    assert len(cleared) == 1
    assert cleared[0].metadata["lifecycle_scope"] == "partial"
    assert cleared[0].metadata["still_active"] == [
        r"c:\users\me\appdata\local\cluely|overlay|hwnd:222"
    ]


def test_window_signals_without_hwnd_keep_titles_separate_before_pid_fallback() -> None:
    first = replace(_overlay(pid=1560), hwnd=None, window_title="parakeetai-desktop")
    second = replace(_overlay(pid=1560), hwnd=None, window_title="pmodule")
    no_title = replace(_overlay(pid=1560), hwnd=None, window_title=None)

    assert signal_fingerprint(first) == (
        r"c:\users\me\appdata\local\cluely|overlay|title:parakeetai-desktop"
    )
    assert signal_fingerprint(second) == (
        r"c:\users\me\appdata\local\cluely|overlay|title:pmodule"
    )
    assert signal_fingerprint(no_title) == (
        r"c:\users\me\appdata\local\cluely|overlay|pid:1560"
    )


def test_overlay_holdover_uses_hwnd_across_title_churn() -> None:
    tracker = EntityLifecycleTracker()
    overlay = replace(_overlay(pid=1560), hwnd=526222, window_title="parakeetai-desktop")
    renamed = replace(overlay, window_title="pmodule")

    seeded = tracker.merge_overlay_holdover([overlay], live_pids={1560})
    tracker.update(seeded, interview_active=False)
    changed = tracker.merge_overlay_holdover([renamed], live_pids={1560})

    assert changed == [renamed]
    events = tracker.update(changed, interview_active=False)
    assert not any(event.metadata.get("lifecycle") == "gone" for event in events)


def test_active_snapshot_uses_live_product_pids_not_session() -> None:
    pk = r"c:\users\me\appdata\local\cluely"
    tracker = EntityLifecycleTracker()
    tracker.update([_overlay(), _process()], interview_active=False)
    tracker._product_pids_seen[pk].update({1111, 2222, 3333})
    tracker.set_live_product_pids({pk: [200, 300]})

    snapshot = tracker.active_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0].instance_count == 2
    assert snapshot[0].live_pids == [200, 300]


def test_active_snapshot_exposes_cluster_confidence_metadata() -> None:
    tracker = EntityLifecycleTracker()
    pk = r"c:\users\me\appdata\local\cluely"
    mic = _microphone(product_key=pk, process_name="Cluely.exe")
    metadata = dict(mic.metadata)
    metadata.update(
        {
            "cluster_confidence": "strong",
            "cluster_classification": "known_cheat",
            "cluster_reasons": ["microphone", "process"],
            "meeting_context": "meeting_active",
        }
    )
    mic = replace(mic, metadata=metadata)

    tracker.update([_process(), mic], interview_active=True)

    snapshot = tracker.active_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0].cluster_confidence == "strong"
    assert snapshot[0].cluster_classification == "known_cheat"
    assert snapshot[0].meeting_context == "meeting_active"
    assert "microphone" in snapshot[0].signals


def test_active_snapshot_uses_template_pid_for_orphan_cluster() -> None:
    tracker = EntityLifecycleTracker()
    orphan = DetectionEvent(
        id="process:orphan",
        severity="high",
        category="process",
        title="Known interview-assist process",
        detail="matched",
        process_name="unknown.exe",
        pid=4242,
        metadata={
            "product_key": "pid:4242",
            "display_name": "unknown.exe",
        },
    )
    tracker.update([orphan], interview_active=False)

    snapshot = tracker.active_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0].product_key == "pid:4242"
    assert snapshot[0].anchor_pid == 4242


def test_session_pids_cleared_after_close_without_prune() -> None:
    pk = r"c:\apps\weathertracker"
    tracker = EntityLifecycleTracker()
    relay = _listener(product_key=pk, port=8096)
    relay = DetectionEvent(
        id=relay.id,
        severity=relay.severity,
        category=relay.category,
        title=relay.title,
        detail=relay.detail,
        process_name=relay.process_name,
        process_path=relay.process_path,
        pid=18936,
        metadata=dict(relay.metadata),
    )
    process = DetectionEvent(
        id="process:wt",
        severity="high",
        category="process",
        title="Known interview-assist process",
        detail="matched",
        process_name="Weather Tracker.exe",
        process_path=r"C:\Apps\WeatherTracker\Weather Tracker.exe",
        pid=15960,
        metadata={
            "product_key": pk,
            "display_name": "Weather Tracker.exe",
        },
    )
    tracker.update([relay, process], interview_active=True)
    tracker.update([], interview_active=True)
    events = tracker.update([], interview_active=True)
    cleared = next(e for e in events if e.severity == "cleared")
    assert cleared.metadata["pids_cleared"] == [15960, 18936]
    identity = format_process_identity(cleared)
    assert identity == "process: Weather Tracker.exe (pids=15960, 18936)"
