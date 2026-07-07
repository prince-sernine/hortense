from __future__ import annotations

from hortense.entity_lifecycle import ProductClusterView
from hortense.watch_dashboard import WatchDashboardFormatter
from hortense.watch_state import WatchState


def test_dashboard_header_uses_meeting_app_names() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.header_lines(
        WatchState(
            meeting_apps=["Zoom", "Chrome"],
            active_clusters=[
                ProductClusterView(
                    product_key="pk",
                    display_name="Weather Tracker.exe",
                    signals=["overlay", "relay listener"],
                    signal_count=2,
                    severity_counts={"high": 1, "medium": 1},
                )
            ],
        )
    )

    assert "meeting apps: Zoom, Chrome" in lines[0]
    assert "interview=" not in lines[0]


def test_dashboard_pre_call_state_lists_static_findings() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.header_lines(
        WatchState(
            pre_call_clusters=[
                ProductClusterView(
                    product_key="pk",
                    display_name="Cluely.exe",
                    signals=["display affinity", "process"],
                    signal_count=2,
                    severity_counts={"high": 2},
                )
            ],
        )
    )

    assert lines[0] == "PRE-CALL findings=2 meeting apps: none"


def test_meeting_apps_detail_caps_long_lists() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.meeting_app_lines(
        WatchState(
            meeting_apps=["Zoom", "Chrome", "Teams", "Edge", "Skype", "Discord", "Slack"]
        ),
        limit=3,
    )

    assert lines == ["Meeting apps", "  Zoom", "  Chrome", "  Teams", "  +4 more"]


def test_cluster_lines_lists_products() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.cluster_lines(
        [
            ProductClusterView(
                product_key="pk",
                display_name="Weather Tracker.exe",
                signals=["overlay", "relay listener"],
                signal_count=2,
                severity_counts={"high": 1, "medium": 1},
            )
        ]
    )

    assert "Weather Tracker.exe" in lines[0]


def test_cluster_lines_shows_main_pid_and_related_count() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.cluster_lines(
        [
            ProductClusterView(
                product_key="pk",
                display_name="Weather Tracker.exe",
                signals=["overlay", "relay listener"],
                signal_count=2,
                severity_counts={"high": 1, "medium": 1},
                anchor_pid=4336,
                instance_count=4,
            )
        ]
    )

    assert "main pid 4336" in lines[0]
    assert "4 live processes" in lines[0]


def test_cluster_lines_shows_capped_live_pid_subline() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.cluster_lines(
        [
            ProductClusterView(
                product_key="pk",
                display_name="parakeetai-desktop [U+2800].exe",
                signals=["display affinity", "overlay", "process"],
                signal_count=3,
                severity_counts={"high": 3},
                anchor_pid=19072,
                instance_count=5,
                live_pids=[2448, 16972, 19028, 19072, 24296],
            )
        ]
    )

    assert "5 live processes" in lines[0]
    assert "pids: 2448, 16972, 19028, 19072 +1 more" in lines[2]


def test_cluster_lines_show_confidence_context() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.cluster_lines(
        [
            ProductClusterView(
                product_key="pk",
                display_name="InterviewMan.exe",
                signals=["microphone", "process", "relay listener"],
                signal_count=3,
                severity_counts={"high": 3},
                cluster_confidence="strong",
                cluster_classification="known_cheat",
                meeting_context="meeting_active",
            )
        ]
    )

    assert lines[2] == (
        "  confidence: strong  class: known_cheat  context: meeting_active"
    )


def test_cluster_lines_skips_pid_subline_for_single_live_process() -> None:
    formatter = WatchDashboardFormatter()
    lines = formatter.cluster_lines(
        [
            ProductClusterView(
                product_key="pk",
                display_name="Lynccontainer.exe",
                signals=["process"],
                signal_count=1,
                severity_counts={"high": 1},
                anchor_pid=21668,
            )
        ]
    )

    assert lines == [
        "Lynccontainer.exe  1 signals  pid 21668",
        "  process",
    ]
