from __future__ import annotations

from hortense.entity import format_pid_list
from hortense.entity_lifecycle import ProductClusterView
from hortense.watch_state import WatchState, meeting_apps_header


def cluster_header_suffix(cluster: ProductClusterView) -> str:
    orphan = cluster.product_key.startswith("pid:")
    if orphan and cluster.anchor_pid is not None:
        return f"  pid {cluster.anchor_pid}"
    if cluster.instance_count and cluster.instance_count > 1 and cluster.anchor_pid:
        return (
            f"  main pid {cluster.anchor_pid}, "
            f"{cluster.instance_count} live processes"
        )
    if cluster.anchor_pid is not None:
        return f"  pid {cluster.anchor_pid}"
    return ""


def cluster_pid_line(cluster: ProductClusterView, *, max_width: int = 72) -> str | None:
    if cluster.product_key.startswith("pid:"):
        return None
    if not cluster.live_pids or len(cluster.live_pids) <= 1:
        return None
    pid_line = format_pid_list(cluster.live_pids, max_width=max_width)
    return pid_line or None


def cluster_confidence_line(cluster: ProductClusterView) -> str | None:
    parts: list[str] = []
    if cluster.cluster_confidence:
        parts.append(f"confidence: {cluster.cluster_confidence}")
    if cluster.cluster_classification:
        parts.append(f"class: {cluster.cluster_classification}")
    if cluster.meeting_context:
        parts.append(f"context: {cluster.meeting_context}")
    return "  ".join(parts) if parts else None


class WatchDashboardFormatter:
    def header_lines(self, state: WatchState) -> list[str]:
        if state.meeting_app_count == 0:
            findings = sum(item.signal_count for item in state.pre_call_clusters)
            return [
                f"PRE-CALL findings={findings} meeting apps: none",
                "-" * 72,
            ]

        active_clusters = len(state.active_clusters)
        active_signals = sum(item.signal_count for item in state.active_clusters)
        high = sum(item.severity_counts.get("high", 0) for item in state.active_clusters)
        medium = sum(item.severity_counts.get("medium", 0) for item in state.active_clusters)
        return [
            (
                f"ACTIVE clusters={active_clusters} signals={active_signals} "
                f"high={high} medium={medium} "
                f"meeting apps: {meeting_apps_header(state.meeting_apps)}"
            ),
            "-" * 72,
        ]

    def cluster_lines(self, clusters: list[ProductClusterView], *, limit: int = 8) -> list[str]:
        if not clusters:
            return ["No active clusters"]
        lines: list[str] = []
        for cluster in clusters[:limit]:
            suffix = cluster_header_suffix(cluster)
            lines.append(f"{cluster.display_name}  {cluster.signal_count} signals{suffix}")
            lines.append(f"  {'  '.join(cluster.signals)}")
            confidence_line = cluster_confidence_line(cluster)
            if confidence_line:
                lines.append(f"  {confidence_line}")
            pid_line = cluster_pid_line(cluster)
            if pid_line:
                lines.append(f"  {pid_line}")
        overflow = len(clusters) - limit
        if overflow > 0:
            lines.append(f"+{overflow} more clusters")
        return lines

    def meeting_app_lines(self, state: WatchState, *, limit: int = 6) -> list[str]:
        if not state.meeting_apps:
            return ["Meeting apps", "  none"]
        lines = ["Meeting apps"]
        for name in state.meeting_apps[:limit]:
            lines.append(f"  {name}")
        overflow = len(state.meeting_apps) - limit
        if overflow > 0:
            lines.append(f"  +{overflow} more")
        return lines
