from __future__ import annotations

from hortense.entity_lifecycle import ProductClusterView
from hortense.models import DetectionEvent
from hortense.watch_state import WatchState
from hortense.watch_tui import WatchTui


PROJECT_LOG_PATH = r"C:\Projects\Hortense\.hortense\events.jsonl"
DEEP_LOG_PATH = (
    r"C:\Projects\Hortense\very\deep\manual\validation"
    r"\folder\.hortense\events.jsonl"
)
PARAKEET_PRODUCT_KEY = (
    r"c:\users\researcher\appdata\local\programs\parakeetai-desktop"
)


def _event(idx: int) -> DetectionEvent:
    return DetectionEvent(
        id=f"event:{idx}",
        severity="high" if idx % 2 else "medium",
        category="process",
        title=f"Event {idx}",
        detail=f"detail {idx}",
        process_name=f"Tool{idx}.exe",
        pid=idx,
    )


def _tui_with_events(count: int) -> WatchTui:
    state = WatchState(events=[_event(idx) for idx in range(count)])
    return WatchTui(
        state,
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=PROJECT_LOG_PATH,
    )


def test_short_path_keeps_footer_compact() -> None:
    path = PROJECT_LOG_PATH

    shortened = WatchTui._short_path(path, max_chars=28)

    assert len(shortened) <= 28
    assert shortened.startswith("C:\\")
    assert "..." in shortened
    assert shortened.endswith(r"events.jsonl")


def test_footer_fragments_use_shortened_jsonl_path() -> None:
    tui = WatchTui(
        WatchState(),
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=DEEP_LOG_PATH,
    )

    footer = "".join(text for _style, text in tui._footer_fragments())

    assert "live" in footer
    assert "recent 100" in footer
    assert "full log:" in footer
    assert "..." in footer
    assert "events.jsonl" in footer


def test_footer_fragments_show_review_mode() -> None:
    tui = _tui_with_events(4)
    tui.state.scroll_offset = 8

    footer = "".join(text for _style, text in tui._footer_fragments())

    assert "review +8" in footer


def test_visible_event_lines_tail_follows_newest_lines() -> None:
    tui = _tui_with_events(6)
    tui.state.scroll_offset = 0

    lines = tui._visible_event_lines(height=4)

    assert any("Event 5" in line for line in lines)
    assert not any("Event 0" in line for line in lines)


def test_visible_event_lines_clamps_overscroll_to_full_view() -> None:
    tui = _tui_with_events(4)
    tui.state.scroll_offset = 999

    lines = tui._visible_event_lines(height=6)

    assert len(lines) == 6
    assert tui.state.scroll_offset == len(tui.state.event_lines()) - 6
    assert any("Event 0" in line for line in lines)


def test_max_scroll_uses_visible_height() -> None:
    tui = _tui_with_events(5)
    total = len(tui.state.event_lines())

    assert tui._max_scroll(height=4) == total - 4


def test_event_fragments_do_not_exceed_visible_height(monkeypatch) -> None:
    tui = _tui_with_events(8)
    monkeypatch.setattr(tui, "_event_view_height", lambda: 5)
    monkeypatch.setattr(tui, "_event_view_width", lambda: 80)

    fragments = tui._event_fragments()
    rendered = "".join(text for _style, text in fragments)

    assert rendered.count("\n") == 5


def test_event_fragments_shorten_long_lines(monkeypatch) -> None:
    tui = WatchTui(
        WatchState(
            events=[
                DetectionEvent(
                    id="event:long",
                    severity="high",
                    category="display_affinity",
                    title="Window excluded from screen capture (WDA_EXCLUDEFROMCAPTURE)",
                    detail="x" * 200,
                )
            ]
        ),
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=PROJECT_LOG_PATH,
    )
    monkeypatch.setattr(tui, "_event_view_height", lambda: 3)
    monkeypatch.setattr(tui, "_event_view_width", lambda: 32)

    fragments = tui._event_fragments()
    lines = "".join(text for _style, text in fragments).splitlines()

    assert all(len(line) <= 32 for line in lines)
    assert any(line.endswith("...") for line in lines)


def test_cluster_fragments_show_main_pid_and_capped_pid_line() -> None:
    tui = WatchTui(
        WatchState(
            pre_call_clusters=[
                ProductClusterView(
                    product_key=PARAKEET_PRODUCT_KEY,
                    display_name="parakeetai-desktop [U+2800].exe",
                    signals=["display affinity", "overlay", "process"],
                    signal_count=3,
                    severity_counts={"high": 3},
                    anchor_pid=19072,
                    instance_count=5,
                    live_pids=[2448, 16972, 19028, 19072, 24296],
                )
            ]
        ),
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=PROJECT_LOG_PATH,
    )

    rendered = "".join(text for _style, text in tui._cluster_fragments())

    assert "parakeetai-desktop [U+2800].exe" in rendered
    assert "3 signals" in rendered
    assert "main pid 19072, 5 live processes" in rendered
    assert "pids: 2448, 16972, 19028, 19072 +1 more" in rendered


def test_cluster_fragments_show_confidence_line() -> None:
    tui = WatchTui(
        WatchState(
            active_clusters=[
                ProductClusterView(
                    product_key=r"c:\apps\interviewman",
                    display_name="InterviewMan.exe",
                    signals=["microphone", "process", "relay listener"],
                    signal_count=3,
                    severity_counts={"high": 3},
                    cluster_confidence="strong",
                    cluster_classification="known_cheat",
                    meeting_context="meeting_active",
                )
            ],
            meeting_apps=["Zoom"],
        ),
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=PROJECT_LOG_PATH,
    )

    rendered = "".join(text for _style, text in tui._cluster_fragments())

    assert "confidence: strong  class: known_cheat  context: meeting_active" in rendered


def test_cluster_fragments_drop_pid_before_confidence_when_tight() -> None:
    clusters = [
        ProductClusterView(
            product_key="pk-a",
            display_name="First.exe",
            signals=["display affinity", "process"],
            signal_count=2,
            severity_counts={"high": 2},
            anchor_pid=100,
            instance_count=4,
            live_pids=[100, 101, 102, 103],
            cluster_confidence="strong",
            cluster_classification="known_cheat",
            meeting_context="meeting_active",
        ),
        ProductClusterView(
            product_key="pk-b",
            display_name="Second.exe",
            signals=["microphone", "process"],
            signal_count=2,
            severity_counts={"high": 2},
            anchor_pid=200,
            instance_count=4,
            live_pids=[200, 201, 202, 203],
            cluster_confidence="strong",
            cluster_classification="known_cheat",
            meeting_context="meeting_active",
        ),
    ]
    tui = WatchTui(
        WatchState(active_clusters=clusters, meeting_apps=["Zoom"]),
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=PROJECT_LOG_PATH,
    )

    rendered = "".join(text for _style, text in tui._cluster_fragments())

    assert "Second.exe" in rendered
    assert "confidence: strong  class: known_cheat  context: meeting_active" in rendered
    assert "pids: 200, 201, 202, 203" not in rendered


def test_cluster_fragments_respect_fixed_pane_budget() -> None:
    clusters = [
        ProductClusterView(
            product_key=f"pk-{idx}",
            display_name=f"Tool{idx}.exe",
            signals=["display affinity", "overlay", "process"],
            signal_count=3,
            severity_counts={"high": 3},
            anchor_pid=1000 + idx,
            instance_count=5,
            live_pids=[1, 2, 3, 4, 5],
        )
        for idx in range(3)
    ]
    tui = WatchTui(
        WatchState(pre_call_clusters=clusters),
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=PROJECT_LOG_PATH,
    )

    rendered = "".join(text for _style, text in tui._cluster_fragments())
    lines = rendered.splitlines()

    assert len(lines) <= 7
    assert "+1 more clusters" in rendered


def test_cluster_fragments_show_orphan_pid_fallback() -> None:
    tui = WatchTui(
        WatchState(
            pre_call_clusters=[
                ProductClusterView(
                    product_key="pid:4242",
                    display_name="unknown",
                    signals=["process"],
                    signal_count=1,
                    severity_counts={"high": 1},
                    anchor_pid=4242,
                    live_pids=[4242, 4243],
                )
            ]
        ),
        poll_once=lambda: None,
        interval_sec=1,
        jsonl_path=PROJECT_LOG_PATH,
    )

    rendered = "".join(text for _style, text in tui._cluster_fragments())

    assert "pid 4242" in rendered
    assert "pids:" not in rendered
