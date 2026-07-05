from __future__ import annotations

from dataclasses import replace
import sys
from typing import Iterable

from hortense.catalog import TrustedCatalog, catalog_status_text, seed_catalog_if_missing
from hortense.config import ScanConfig, Signatures
from hortense.entity import (
    build_process_index,
    display_name,
    product_key as resolve_product_key,
)
from hortense.entity_lifecycle import EntityLifecycleTracker, is_static_watch_event
from hortense.impersonation import impersonation_events
from hortense.models import DetectionEvent

EVIDENCE_CATEGORIES = {
    "display_affinity",
    "overlay",
    "process",
    "stealth_relay",
    "microphone",
}


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
    merged: dict[tuple[str, str, str], DetectionEvent] = {}
    passthrough: list[DetectionEvent] = []
    window_categories = {"display_affinity", "overlay"}

    for event in events:
        if event.category not in window_categories:
            passthrough.append(event)
            continue

        pk = str(event.metadata.get("product_key") or "")
        key = (
            event.category,
            pk,
            (event.window_title or "").casefold(),
        )
        current = merged.get(key)
        if current is None or event.score > current.score:
            merged[key] = event

    return passthrough + list(merged.values())


def _attach_product_keys(
    events: list[DetectionEvent],
    *,
    by_pid: dict,
    live_pids: set[int],
    tree_roots: list[str],
) -> list[DetectionEvent]:
    enriched: list[DetectionEvent] = []
    for event in events:
        pid = event.pid
        attributed = event.metadata.get("attributed_pid")
        if isinstance(attributed, int):
            pid = attributed
        pk = resolve_product_key(
            pid,
            event.process_path,
            by_pid=by_pid,
            tree_roots=tree_roots,
            live_pids=live_pids,
        )
        metadata = dict(event.metadata)
        metadata["product_key"] = pk
        metadata["display_name"] = display_name(event.process_path, event.process_name)
        enriched.append(replace(event, metadata=metadata))
    return enriched


def correlate_by_product_key(events: Iterable[DetectionEvent]) -> list[DetectionEvent]:
    collected = list(events)
    evidence_by_product: dict[str, set[str]] = {}

    for event in collected:
        pk = str(event.metadata.get("product_key") or "")
        if not pk or event.category not in EVIDENCE_CATEGORIES:
            continue
        evidence_by_product.setdefault(pk, set()).add(event.category)

    correlated: list[DetectionEvent] = []
    for event in collected:
        pk = str(event.metadata.get("product_key") or "")
        matched = evidence_by_product.get(pk, set())

        if event.category == "microphone" and len(matched) > 1:
            metadata = dict(event.metadata)
            metadata["confidence"] = "strong"
            metadata["correlated_categories"] = sorted(matched - {"microphone"})
            correlated.append(
                replace(
                    event,
                    severity="high",
                    title="Microphone capture attributed to hidden-window host",
                    metadata=metadata,
                )
            )
            continue

        if event.category == "stealth_relay" and matched - {"stealth_relay"}:
            metadata = dict(event.metadata)
            metadata["confidence"] = "strong"
            metadata["correlated_categories"] = sorted(matched - {"stealth_relay"})
            correlated.append(
                replace(
                    event,
                    severity="high",
                    title="Suspicious stealth relay correlated with interview-assist evidence",
                    metadata=metadata,
                )
            )
            continue

        correlated.append(event)

    return correlated


def _resolve_trust_lists(signatures: Signatures, cfg: ScanConfig) -> TrustedCatalog:
    if cfg.sync_catalog:
        seed_catalog_if_missing()
    return TrustedCatalog.load_merged(
        signatures_trust_publishers=signatures.trust_publishers,
        signatures_companion=signatures.companion_processes,
        signatures_trust_paths=signatures.trust_path_prefixes,
    )


def _debug_report(stage: str, events: list[DetectionEvent], *, cfg: ScanConfig) -> None:
    if not cfg.debug:
        return
    counts: dict[str, int] = {}
    for event in events:
        counts[event.category] = counts.get(event.category, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
    print(f"hortense debug [{stage}]: {len(events)} events ({summary})", file=sys.stderr)


def run_scan(
    config: ScanConfig | None = None,
    lifecycle_tracker: EntityLifecycleTracker | None = None,
) -> list[DetectionEvent]:
    cfg = config or ScanConfig()
    signatures = cfg.resolve_signatures()
    catalog = _resolve_trust_lists(signatures, cfg)
    if cfg.sync_catalog and catalog.is_stale():
        print(
            f"hortense: trust catalog cache is stale ({catalog.age_days()} days). "
            "Run: hortense catalog update",
            file=sys.stderr,
        )

    core = _import_core()
    allow = signatures.allowlist_processes
    allow_paths = signatures.allowlist_path_substrings

    events: list[DetectionEvent] = []
    events.extend(_normalize(core.scan_display_affinity(allow, allow_paths)))
    events.extend(_normalize(core.scan_overlays(allow, allow_paths)))
    events.extend(_normalize(_scan_processes(core, signatures)))
    events.extend(_normalize(_scan_microphone(core, signatures)))
    events.extend(_normalize(_scan_network(core, signatures)))
    relay_events = _normalize(
        _scan_stealth_relays(core, signatures, catalog)
    )
    events.extend(relay_events)
    _debug_report("sensors", events, cfg=cfg)

    snapshot = core.process_snapshot()
    by_pid, live_pids = build_process_index(snapshot)
    events = _attach_product_keys(
        events,
        by_pid=by_pid,
        live_pids=live_pids,
        tree_roots=signatures.process_tree_roots,
    )

    events = correlate_by_product_key(events)
    events = impersonation_events(events, catalog.processes)
    _debug_report("fusion", events, cfg=cfg)

    interview_active = bool(core.interview_session_active(signatures.interview_processes))
    if cfg.debug:
        print(f"hortense debug [gate]: interview_active={interview_active}", file=sys.stderr)

    if cfg.watch_mode and lifecycle_tracker is not None and interview_active:
        watch_events = [e for e in events if is_static_watch_event(e)]
        lifecycle = lifecycle_tracker.update(
            watch_events,
            interview_active=interview_active,
        )
        events = [e for e in events if not is_static_watch_event(e)]
        events.extend(lifecycle)
    elif cfg.watch_mode and lifecycle_tracker is not None and not interview_active:
        print(
            "hortense: no interview app detected (Zoom/Teams/Chrome). "
            "Showing static findings until a call starts.",
            file=sys.stderr,
        )

    collapsed = _collapse_window_events(_collapse_process_events(_dedupe(events)))
    _debug_report("output", collapsed, cfg=cfg)
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


def _scan_stealth_relays(core, signatures: Signatures, catalog: TrustedCatalog) -> list[dict]:
    return core.scan_stealth_relays(
        signatures.allowlist_processes,
        signatures.allowlist_path_substrings,
        signatures.interview_processes,
        catalog.trust_publishers,
        catalog.companion_processes,
        catalog.trust_path_prefixes,
        signatures.suspicious_path_prefixes,
        signatures.process_names,
        signatures.path_substrings,
    )


def has_high_severity(events: Iterable[DetectionEvent]) -> bool:
    return any(event.severity == "high" for event in events)


# Backward-compatible private aliases for tests.
_correlate_microphone_attribution = correlate_by_product_key
_correlate_relay_evidence = correlate_by_product_key


def catalog_status_report(signatures_path=None) -> str:
    signatures = Signatures.load(signatures_path)
    catalog = TrustedCatalog.load_merged(
        signatures_trust_publishers=signatures.trust_publishers,
        signatures_companion=signatures.companion_processes,
        signatures_trust_paths=signatures.trust_path_prefixes,
    )
    return catalog_status_text(catalog)
