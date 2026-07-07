from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from hortense.entity import format_process_identity, render_detail_line
from hortense.entity_lifecycle import ProductClusterView, format_signal_label
from hortense.models import DetectionEvent


MEETING_APP_LABELS = {
    "zoom.exe": "Zoom",
    "teams.exe": "Teams",
    "ms-teams.exe": "Teams",
    "chrome.exe": "Chrome",
    "msedge.exe": "Edge",
    "webex.exe": "Webex",
    "slack.exe": "Slack",
    "skype.exe": "Skype",
    "discord.exe": "Discord",
}


@dataclass
class WatchState:
    active_clusters: list[ProductClusterView] = field(default_factory=list)
    pre_call_clusters: list[ProductClusterView] = field(default_factory=list)
    meeting_apps: list[str] = field(default_factory=list)
    raw_meeting_apps: list[str] = field(default_factory=list)
    events: list[DetectionEvent] = field(default_factory=list)
    scroll_offset: int = 0

    @property
    def meeting_app_count(self) -> int:
        return len(self.meeting_apps)

    def event_lines(self) -> list[str]:
        lines: list[str] = []
        for event in self.events:
            badge = "[CLEARED]" if event.severity == "cleared" else f"[{event.severity.upper()}]"
            lines.append(f"{badge} {event.title}")
            if event.detail:
                lines.append(f"  {render_detail_line(event)}")
            identity = format_process_identity(event)
            if identity:
                lines.append(f"  {identity}")
            if event.window_title:
                lines.append(f"  window: {event.window_title}")
            still_active = event.metadata.get("still_active")
            if isinstance(still_active, list) and still_active:
                labels = ", ".join(format_signal_label(str(item)) for item in still_active)
                lines.append(f"  still active: {labels}")
            lines.append("")
        return lines


def meeting_app_names(snapshot: list[dict], meeting_processes: list[str]) -> tuple[list[str], list[str]]:
    wanted = {name.casefold() for name in meeting_processes}
    raw = sorted(
        {
            str(row.get("exe") or "").casefold()
            for row in snapshot
            if str(row.get("exe") or "").casefold() in wanted
        }
    )
    labels = [MEETING_APP_LABELS.get(name, _label_from_exe(name)) for name in raw]
    return labels, raw


def meeting_apps_header(apps: list[str], *, limit: int = 3) -> str:
    if not apps:
        return "none"
    visible = apps[:limit]
    extra = len(apps) - len(visible)
    label = ", ".join(visible)
    if extra > 0:
        label = f"{label} +{extra}"
    return label


def product_views_from_events(events: list[DetectionEvent]) -> list[ProductClusterView]:
    grouped: dict[str, list[DetectionEvent]] = defaultdict(list)
    for event in events:
        if event.metadata.get("lifecycle"):
            continue
        if event.severity == "cleared":
            continue
        product_key = str(
            event.metadata.get("product_key")
            or event.process_path
            or event.process_name
            or event.id
        )
        grouped[product_key].append(event)

    views: list[ProductClusterView] = []
    for product_key, items in sorted(grouped.items()):
        severity_counts: dict[str, int] = defaultdict(int)
        signals: set[str] = set()
        display_name = "unknown"
        for item in items:
            severity_counts[item.severity] += 1
            signals.add(item.category.replace("_", " "))
            display_name = str(
                item.metadata.get("display_name")
                or item.process_name
                or display_name
            )
        views.append(
            ProductClusterView(
                product_key=product_key,
                display_name=display_name,
                signals=sorted(signals),
                signal_count=len(items),
                severity_counts=dict(severity_counts),
            )
        )
    return views


def display_key(event: DetectionEvent) -> str:
    lifecycle = event.metadata.get("lifecycle")
    if lifecycle:
        return event.id
    product_key = str(event.metadata.get("product_key") or "")
    match_reason = str(event.metadata.get("match_reason") or "")
    return "|".join(
        [
            event.category,
            product_key,
            event.process_name or "",
            event.window_title or "",
            event.title,
            match_reason,
        ]
    )


def ordered_for_watch(events: list[DetectionEvent]) -> list[DetectionEvent]:
    return sorted(events, key=_watch_order_key)


def _watch_order_key(event: DetectionEvent) -> tuple[int, int, str]:
    lifecycle = str(event.metadata.get("lifecycle") or "")
    if lifecycle in {"appeared", "returned"}:
        phase = 0
    elif event.severity == "cleared" or lifecycle == "cleared":
        phase = 3
    elif lifecycle == "gone":
        phase = 2
    else:
        phase = 1
    severity_order = {"high": 0, "medium": 1, "low": 2, "cleared": 3}.get(event.severity, 4)
    return (phase, severity_order, event.id)


def _label_from_exe(name: str) -> str:
    base = name.rsplit("\\", 1)[-1]
    if base.casefold().endswith(".exe"):
        base = base[:-4]
    return base[:1].upper() + base[1:]
