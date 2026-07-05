from __future__ import annotations

from dataclasses import replace
import sys
from typing import Iterable

from hortense.config import ScanConfig, Signatures
from hortense.models import DetectionEvent
from hortense.relay_lifecycle import RelayLifecycleTracker, is_static_listener_event


def require_windows() -> None:
    if sys.platform != "win32":
        raise SystemExit("hortense requires Windows (win32).")


def _import_core():
    require_windows()
    try:
        from hortense import _core
    except ImportError as exc:
        raise SystemExit(
            "hortense._core extension missing. Run: maturin develop --release"
        ) from exc
    return _core


def _normalize(raw_events: Iterable[dict]) -> list[DetectionEvent]:
    return [DetectionEvent.from_raw(item) for item in raw_events]


def _dedupe(events: Iterable[DetectionEvent]) -> list[DetectionEvent]:
    seen: set[str] = set()
    ordered: list[DetectionEvent] = []
    for event in sorted(events, key=lambda e: (-e.score, e.id)):
        if event.id in seen:
            continue
        seen.add(event.id)
        ordered.append(event)
    return ordered


def _collapse_process_events(events: Iterable[DetectionEvent]) -> list[DetectionEvent]:
    merged: dict[tuple[str, str, str], DetectionEvent] = {}
    passthrough: list[DetectionEvent] = []

    for event in events:
        if event.category != "process":
            passthrough.append(event)
            continue

        match_reason = str(event.metadata.get("match_reason", ""))
        identity = (
            (event.process_path or event.process_name or "").casefold(),
            match_reason,
        )
        key = ("process", identity[0], identity[1])
        current = merged.get(key)
        if current is None or event.score > current.score:
            merged[key] = event

    return passthrough + list(merged.values())


def _collapse_window_events(events: Iterable[DetectionEvent]) -> list[DetectionEvent]:
    """Electron apps often expose multiple HWNDs for one visible window."""
    merged: dict[tuple[str, int | None, str, str], DetectionEvent] = {}
    passthrough: list[DetectionEvent] = []
    window_categories = {"display_affinity", "overlay"}

    for event in events:
        if event.category not in window_categories:
            passthrough.append(event)
            continue

        key = (
            event.category,
            event.pid,
            (event.process_path or event.process_name or "").casefold(),
            (event.window_title or "").casefold(),
        )
        current = merged.get(key)
        if current is None or event.score > current.score:
            merged[key] = event

    return passthrough + list(merged.values())


def _correlate_microphone_attribution(
    events: Iterable[DetectionEvent],
) -> list[DetectionEvent]:
    evidence_by_pid: dict[int, set[str]] = {}
    evidence_categories = {"display_affinity", "overlay", "process", "stealth_relay"}

    collected = list(events)
    for event in collected:
        if event.pid is None or event.category not in evidence_categories:
            continue
        evidence_by_pid.setdefault(event.pid, set()).add(event.category)

    correlated: list[DetectionEvent] = []
    for event in collected:
        if event.category != "microphone":
            correlated.append(event)
            continue

        attributed_pid = event.metadata.get("attributed_pid")
        if not isinstance(attributed_pid, int):
            correlated.append(event)
            continue

        matched_categories = evidence_by_pid.get(attributed_pid)
        if not matched_categories:
            correlated.append(event)
            continue

        metadata = dict(event.metadata)
        metadata["confidence"] = "strong"
        metadata["correlated_categories"] = sorted(matched_categories)
        correlated.append(
            replace(
                event,
                severity="high",
                title="Microphone capture attributed to hidden-window host",
                metadata=metadata,
            )
        )

    return correlated


def _correlate_relay_evidence(events: Iterable[DetectionEvent]) -> list[DetectionEvent]:
    evidence_by_pid: dict[int, set[str]] = {}
    collected = list(events)

    for event in collected:
        if event.pid is None:
            continue
        if event.category in {"display_affinity", "overlay", "process"}:
            evidence_by_pid.setdefault(event.pid, set()).add(event.category)

    correlated: list[DetectionEvent] = []
    for event in collected:
        if event.category != "stealth_relay":
            correlated.append(event)
            continue

        pid = event.pid
        if pid is None:
            correlated.append(event)
            continue

        matched = evidence_by_pid.get(pid)
        if not matched:
            correlated.append(event)
            continue

        metadata = dict(event.metadata)
        metadata["confidence"] = "strong"
        metadata["correlated_categories"] = sorted(matched)
        correlated.append(
            replace(
                event,
                severity="high",
                title="Suspicious stealth relay correlated with interview-assist evidence",
                metadata=metadata,
            )
        )

    return correlated


def run_scan(
    config: ScanConfig | None = None,
    lifecycle_tracker: RelayLifecycleTracker | None = None,
) -> list[DetectionEvent]:
    cfg = config or ScanConfig()
    signatures = cfg.resolve_signatures()
    core = _import_core()

    allow = signatures.allowlist_processes
    allow_paths = signatures.allowlist_path_substrings

    events: list[DetectionEvent] = []
    events.extend(_normalize(core.scan_display_affinity(allow, allow_paths)))
    events.extend(_normalize(core.scan_overlays(allow, allow_paths)))
    events.extend(_normalize(_scan_processes(core, signatures)))
    events.extend(_normalize(_scan_microphone(core, signatures)))
    events.extend(_normalize(_scan_network(core, signatures)))
    relay_events = _normalize(_scan_stealth_relays(core, signatures))
    events.extend(relay_events)

    interview_active = bool(core.interview_session_active(signatures.interview_processes))

    if cfg.watch_mode and lifecycle_tracker is not None:
        listener_events = [e for e in relay_events if is_static_listener_event(e)]
        lifecycle = lifecycle_tracker.update(
            listener_events,
            interview_active=interview_active,
        )
        events = [e for e in events if not is_static_listener_event(e)]
        events.extend(lifecycle)

    events = _correlate_microphone_attribution(events)
    events = _correlate_relay_evidence(events)
    collapsed = _collapse_window_events(_collapse_process_events(_dedupe(events)))
    return sorted(collapsed, key=lambda e: (-e.score, e.category, e.id))


def _scan_processes(core, signatures: Signatures) -> list[dict]:
    return core.scan_processes(
        signatures.process_names,
        signatures.path_substrings,
        signatures.allowlist_processes,
        signatures.allowlist_path_substrings,
        signatures.process_tree_roots,
    )


def _scan_microphone(core, signatures: Signatures) -> list[dict]:
    return core.scan_microphone_sessions(
        signatures.allowlist_processes,
        signatures.allowlist_path_substrings,
        signatures.interview_processes,
        signatures.process_names,
        signatures.path_substrings,
        signatures.process_tree_roots,
    )


def _scan_network(core, signatures: Signatures) -> list[dict]:
    return core.scan_network(
        signatures.network_domains,
        signatures.allowlist_processes,
        signatures.allowlist_path_substrings,
        signatures.interview_processes,
    )


def _scan_stealth_relays(core, signatures: Signatures) -> list[dict]:
    return core.scan_stealth_relays(
        signatures.allowlist_processes,
        signatures.allowlist_path_substrings,
        signatures.interview_processes,
        signatures.trust_publishers,
        signatures.companion_processes,
        signatures.trust_path_prefixes,
        signatures.suspicious_path_prefixes,
        signatures.process_names,
        signatures.path_substrings,
    )


def has_high_severity(events: Iterable[DetectionEvent]) -> bool:
    return any(event.severity == "high" for event in events)
