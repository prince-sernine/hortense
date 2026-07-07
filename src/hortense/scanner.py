from __future__ import annotations

from dataclasses import replace
import json
import sys
from typing import Iterable

from hortense.catalog import TrustedCatalog, catalog_status_text, seed_catalog_if_missing
from hortense.config import ScanConfig, Signatures
from hortense.entity import (
    attach_cluster_identity,
    build_process_index,
    compute_anchor_pids,
    format_executable_label,
    live_instance_counts,
    live_product_pids,
    normalize_path,
    prefer_process_event,
    product_key as resolve_product_key,
)
from hortense.entity_lifecycle import (
    EntityLifecycleTracker,
    RELAY_RETENTION_CATEGORIES,
    RELAY_THREAT_CATEGORIES,
    is_static_watch_event,
)
from hortense.impersonation import impersonation_events
from hortense.models import DetectionEvent
from hortense.watch_state import meeting_app_names

EVIDENCE_CATEGORIES = {
    "display_affinity",
    "overlay",
    "process",
    "stealth_relay",
    "microphone",
    "known_app_anomaly",
}

BROWSER_MEETING_HOSTS = {"chrome.exe", "msedge.exe"}

MIC_THREAT_CATEGORIES = {
    "process",
    "overlay",
    "display_affinity",
    "stealth_relay",
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
        anchor = event.metadata.get("anchor_pid")
        anchor_pid = anchor if isinstance(anchor, int) else None
        if current is None:
            merged[key] = event
        else:
            current_anchor = current.metadata.get("anchor_pid")
            current_anchor_pid = current_anchor if isinstance(current_anchor, int) else None
            merged[key] = prefer_process_event(
                current,
                event,
                current_anchor_pid or anchor_pid,
            )

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
        label, obfuscation_meta = format_executable_label(
            event.process_path,
            event.process_name,
        )
        metadata["display_name"] = label
        metadata.update(obfuscation_meta)
        enriched.append(replace(event, metadata=metadata))
    return enriched


def known_app_anomaly_events(
    snapshot: list[dict],
    catalog_processes: list[dict],
    *,
    suspicious_path_prefixes: list[str],
    signer_lookup,
) -> list[DetectionEvent]:
    catalog_by_name = {
        str(entry.get("name") or "").casefold(): entry
        for entry in catalog_processes
        if entry.get("name")
    }
    events: list[DetectionEvent] = []
    seen_paths: set[str] = set()
    for row in snapshot:
        exe = str(row.get("exe") or "")
        entry = catalog_by_name.get(exe.casefold())
        path = str(row.get("path") or "")
        if not entry or not path:
            continue
        normalized = normalize_path(path)
        if normalized in seen_paths:
            continue
        seen_paths.add(normalized)

        signer = signer_lookup(path) or {}
        expected_publishers = _catalog_publishers(entry)
        expected_paths = [str(item) for item in (entry.get("path_prefixes") or []) if item]
        publisher = str(signer.get("publisher") or "")
        signature_valid = bool(signer.get("signature_valid"))
        signed = bool(signer.get("signed"))

        reasons: list[str] = []
        if not signed:
            reasons.append("unsigned")
        elif not signature_valid:
            reasons.append("invalid signature")
        if expected_publishers and publisher and not _publisher_matches_any(publisher, expected_publishers):
            reasons.append("wrong publisher")
        if expected_publishers and not publisher:
            reasons.append("publisher unknown")
        if expected_paths and not _path_matches_any(path, expected_paths):
            reasons.append("unexpected path")
        elif not expected_paths and _path_matches_any(path, suspicious_path_prefixes):
            reasons.append("suspicious path")

        if not reasons:
            continue

        reason_text = ", ".join(reasons)
        events.append(
            DetectionEvent(
                id=f"known_app_anomaly:{normalized}",
                severity="medium",
                category="known_app_anomaly",
                title=f"Known app integrity anomaly - {exe}",
                detail=(
                    f"{exe} looks like a cataloged app, but signer/path trust failed "
                    f"({reason_text}). This may be a modified or unofficial build."
                ),
                process_name=exe,
                process_path=path,
                pid=int(row["pid"]) if row.get("pid") is not None else None,
                metadata={
                    "signed": signed,
                    "signature_valid": signature_valid,
                    "publisher": publisher or None,
                    "expected_publishers": expected_publishers,
                    "expected_path_prefixes": expected_paths,
                    "anomaly_reasons": reasons,
                },
            )
        )
    return events


def _catalog_publishers(entry: dict) -> list[str]:
    publishers = entry.get("publishers")
    if publishers is None:
        publishers = [entry.get("publisher")]
    return [str(item) for item in publishers or [] if item]


def _publisher_matches_any(publisher: str, expected: list[str]) -> bool:
    hay = publisher.casefold()
    return any(item.casefold() in hay for item in expected)


def _path_matches_any(path: str, prefixes: list[str]) -> bool:
    normalized = normalize_path(path)
    return any(normalize_path(prefix) in normalized for prefix in prefixes)


def _surface_relays(
    events: list[DetectionEvent],
    *,
    interview_active: bool,
) -> list[DetectionEvent]:
    if interview_active:
        return events

    cluster_categories: dict[str, set[str]] = {}
    for event in events:
        pk = str(event.metadata.get("product_key") or "")
        if pk:
            cluster_categories.setdefault(pk, set()).add(event.category)
    retained = {
        pk
        for pk, cats in cluster_categories.items()
        if cats & RELAY_RETENTION_CATEGORIES
    }

    surfaced: list[DetectionEvent] = []
    for event in events:
        if event.category == "stealth_relay":
            pk = str(event.metadata.get("product_key") or "")
            if pk not in retained:
                continue
        surfaced.append(event)
    return surfaced


def _surface_microphones(
    events: list[DetectionEvent],
    *,
    interview_active: bool,
) -> list[DetectionEvent]:
    if interview_active:
        return events

    cluster_categories: dict[str, set[str]] = {}
    for event in events:
        pk = str(event.metadata.get("product_key") or "")
        if pk:
            cluster_categories.setdefault(pk, set()).add(event.category)

    surfaced: list[DetectionEvent] = []
    for event in events:
        if event.category == "microphone":
            pk = str(event.metadata.get("product_key") or "")
            siblings = cluster_categories.get(pk, set()) - {"microphone"}
            if not siblings:
                continue
        surfaced.append(event)
    return surfaced


def _relay_has_strong_shape(event: DetectionEvent) -> bool:
    # Native code grades a broad bind (all interfaces, or a non-localhost "other")
    # louder than a localhost-only listener. Normalize so both the hyphen label from
    # Rust and the underscore form used in fixtures read the same.
    scope = str(event.metadata.get("bind_scope") or "").replace("_", "-")
    return scope in {"all-interfaces", "other"}


def _anomaly_reasons_are_masquerade(reasons: Iterable[str]) -> bool:
    # Wrong publisher / unexpected path smell like impersonation, not just an
    # unofficial-but-honest build. Those earn a medium rather than a low.
    return any(
        ("wrong publisher" in reason) or ("unexpected path" in reason)
        for reason in reasons
    )


def _cluster_classification(categories: set[str]) -> str:
    if "process" in categories:
        return "known_cheat"
    if "known_app_anomaly" in categories:
        return "modified_known_app"
    if "microphone" in categories and categories & MIC_THREAT_CATEGORIES:
        return "suspicious_stack"
    return "unknown_single_signal"


def _cluster_confidence(
    categories: set[str],
    *,
    anomaly_reasons: list[str],
) -> str:
    if "process" in categories:
        return "strong"
    if "microphone" in categories and categories & MIC_THREAT_CATEGORIES:
        return "strong"
    if "microphone" in categories and "known_app_anomaly" in categories:
        if categories & {"stealth_relay", "overlay", "display_affinity"}:
            return "strong"
        return "corroborated"
    if "known_app_anomaly" in categories and anomaly_reasons:
        return "corroborated"
    return "heuristic"


def _assessment_metadata(
    product_key: str,
    categories: set[str],
    *,
    anomaly_reasons: list[str],
    meeting_context: str,
) -> dict:
    return {
        "cluster_classification": _cluster_classification(categories),
        "cluster_confidence": _cluster_confidence(
            categories,
            anomaly_reasons=anomaly_reasons,
        ),
        "cluster_reasons": sorted(categories),
        "meeting_context": meeting_context,
        "product_key": product_key,
    }


def apply_cluster_assessments(
    events: Iterable[DetectionEvent],
    *,
    meeting_context: str,
) -> list[DetectionEvent]:
    collected = list(events)
    categories_by_product: dict[str, set[str]] = {}
    anomaly_reasons_by_product: dict[str, list[str]] = {}
    for event in collected:
        pk = str(event.metadata.get("product_key") or "")
        if not pk:
            continue
        if event.category in EVIDENCE_CATEGORIES:
            categories_by_product.setdefault(pk, set()).add(event.category)
        if event.category == "known_app_anomaly":
            reasons = [
                str(item)
                for item in (event.metadata.get("anomaly_reasons") or [])
            ]
            anomaly_reasons_by_product.setdefault(pk, []).extend(reasons)

    assessed: list[DetectionEvent] = []
    for event in collected:
        if event.category not in {"microphone", "stealth_relay"}:
            assessed.append(event)
            continue
        pk = str(event.metadata.get("product_key") or "")
        metadata = dict(event.metadata)
        metadata.update(
            _assessment_metadata(
                pk,
                categories_by_product.get(pk, set()),
                anomaly_reasons=anomaly_reasons_by_product.get(pk, []),
                meeting_context=meeting_context,
            )
        )
        assessed.append(replace(event, metadata=metadata))
    return assessed


def correlate_by_product_key(events: Iterable[DetectionEvent]) -> list[DetectionEvent]:
    collected = list(events)
    evidence_by_product: dict[str, set[str]] = {}
    anomaly_reasons_by_product: dict[str, list[str]] = {}

    for event in collected:
        pk = str(event.metadata.get("product_key") or "")
        if not pk:
            continue
        if event.category in EVIDENCE_CATEGORIES:
            evidence_by_product.setdefault(pk, set()).add(event.category)
        if event.category == "known_app_anomaly":
            reasons = [
                str(item)
                for item in (event.metadata.get("anomaly_reasons") or [])
            ]
            anomaly_reasons_by_product.setdefault(pk, []).extend(reasons)

    correlated: list[DetectionEvent] = []
    for event in collected:
        pk = str(event.metadata.get("product_key") or "")
        matched = evidence_by_product.get(pk, set())

        if event.category == "microphone" and len(matched) > 1:
            correlated_categories = sorted(matched - {"microphone"})
            threat_present = bool(set(correlated_categories) & MIC_THREAT_CATEGORIES)
            anomaly_only = (
                "known_app_anomaly" in correlated_categories
                and not threat_present
            )
            metadata = dict(event.metadata)
            metadata["confidence"] = "corroborated" if anomaly_only else "strong"
            metadata["correlated_categories"] = correlated_categories
            severity = "medium" if anomaly_only else "high"
            title = (
                "Microphone capture on modified app"
                if anomaly_only
                else "Microphone capture attributed to suspicious product"
            )
            correlated.append(
                replace(
                    event,
                    severity=severity,
                    title=title,
                    metadata=metadata,
                )
            )
            continue

        if event.category == "stealth_relay" and matched - {"stealth_relay"}:
            correlated_categories = sorted(matched - {"stealth_relay"})
            threat_present = bool(set(correlated_categories) & RELAY_THREAT_CATEGORIES)
            anomaly_present = "known_app_anomaly" in correlated_categories
            metadata = dict(event.metadata)
            metadata["correlated_categories"] = correlated_categories

            if anomaly_present and not threat_present:
                # A relay on a modified known app with no cheat-shaped signals is
                # informational, not an accusation. Grade it by shape and by how
                # much the anomaly smells like impersonation.
                reasons = anomaly_reasons_by_product.get(pk, [])
                loud = _relay_has_strong_shape(event) or _anomaly_reasons_are_masquerade(reasons)
                severity = "medium" if loud else "low"
                name = event.process_name or "modified app"
                metadata["confidence"] = "corroborated"
                metadata["relay_tier"] = "anomaly_informational"
                correlated.append(
                    replace(
                        event,
                        severity=severity,
                        title=f"Open listener on modified app - {name}",
                        metadata=metadata,
                    )
                )
                continue

            metadata["confidence"] = "strong"
            metadata["relay_tier"] = "threat"
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


def _debug_relay_signers(events: list[DetectionEvent], *, cfg: ScanConfig) -> None:
    if not cfg.debug:
        return
    for event in events:
        publisher = event.metadata.get("publisher") or "unknown"
        signed = event.metadata.get("signed")
        signature_valid = event.metadata.get("signature_valid")
        trust_tier = event.metadata.get("trust_tier") or "unknown"
        print(
            "hortense debug [relay-signer]: "
            f"{event.process_name or 'unknown'} "
            f"signed={signed} signature_valid={signature_valid} "
            f"publisher={publisher} trust={trust_tier} "
            f"path={event.process_path or 'unknown'}",
            file=sys.stderr,
        )


def _debug_microphone_diagnostics(core, signatures: Signatures, *, cfg: ScanConfig) -> None:
    if not cfg.debug or not hasattr(core, "microphone_diagnostics"):
        return
    try:
        rows = core.microphone_diagnostics(
            signatures.allowlist_processes,
            signatures.allowlist_path_substrings,
            signatures.process_names,
            signatures.path_substrings,
            signatures.process_tree_roots,
        )
    except Exception as exc:  # pragma: no cover - diagnostic only
        print(f"hortense debug [mic-proof]: error={exc}", file=sys.stderr)
        return

    if not rows:
        print("hortense debug [mic-proof]: no active capture sessions", file=sys.stderr)
        return
    for raw in rows:
        try:
            row = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            print(f"hortense debug [mic-proof]: raw={raw}", file=sys.stderr)
            continue
        if row.get("error"):
            print(
                "hortense debug [mic-proof]: "
                f"action={row.get('final_action')} error={row.get('error')}",
                file=sys.stderr,
            )
            continue
        sources = ", ".join(row.get("endpoint_sources") or []) or "unknown"
        attributed = row.get("attributed_process_name") or "none"
        print(
            "hortense debug [mic-proof]: "
            f"pid={row.get('pid')} "
            f"process={row.get('process_name') or 'unknown'} "
            f"allowlisted={row.get('allowlisted')} "
            f"action={row.get('final_action')} "
            f"attributed={attributed} "
            f"reason={row.get('attribution_reason') or 'none'} "
            f"sources={sources} "
            f"path={row.get('process_path') or 'unknown'}",
            file=sys.stderr,
        )


def _native_meeting_processes(meeting_processes: list[str]) -> list[str]:
    return [
        name
        for name in meeting_processes
        if name.casefold() not in BROWSER_MEETING_HOSTS
    ]


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
    _debug_microphone_diagnostics(core, signatures, cfg=cfg)
    events.extend(_normalize(_scan_microphone(core, signatures)))
    events.extend(_normalize(_scan_network(core, signatures)))
    native_meeting_processes = _native_meeting_processes(signatures.interview_processes)

    relay_events = _normalize(
        _scan_stealth_relays(core, signatures, catalog, native_meeting_processes)
    )
    _debug_relay_signers(relay_events, cfg=cfg)
    events.extend(relay_events)
    _debug_report("sensors", events, cfg=cfg)

    snapshot = core.process_snapshot()
    by_pid, live_pids = build_process_index(snapshot)
    events.extend(
        known_app_anomaly_events(
            snapshot,
            catalog.processes,
            suspicious_path_prefixes=signatures.suspicious_path_prefixes,
            signer_lookup=core.signer_info,
        )
    )
    events = _attach_product_keys(
        events,
        by_pid=by_pid,
        live_pids=live_pids,
        tree_roots=signatures.process_tree_roots,
    )

    events = correlate_by_product_key(events)
    events = impersonation_events(events, catalog.processes)
    _debug_report("fusion", events, cfg=cfg)

    names, raw_names = meeting_app_names(snapshot, native_meeting_processes)
    interview_active = bool(names)
    if lifecycle_tracker is not None:
        lifecycle_tracker.meeting_app_count = len(names)
        lifecycle_tracker.meeting_app_names = names
        lifecycle_tracker.raw_meeting_app_names = raw_names
    if cfg.debug:
        print(
            "hortense debug [gate]: "
            f"meeting_apps={', '.join(names) or 'none'} "
            f"raw={', '.join(raw_names) or 'none'}",
            file=sys.stderr,
        )

    meeting_context = "meeting_active" if interview_active else "pre_call"
    events = apply_cluster_assessments(events, meeting_context=meeting_context)

    # Relays are always scanned in native code now; the surfacing policy lives here
    # and applies to both watch and one-shot scan. A bare relay (no meeting, no
    # anomaly, no threat sibling) is call-context noise and is dropped. Retained
    # relays (anomaly or threat cluster) and any relay during a call stay.
    events = _surface_relays(events, interview_active=interview_active)
    if cfg.watch_mode:
        events = _surface_microphones(events, interview_active=interview_active)

    anchor_pids = compute_anchor_pids(events, by_pid)
    instance_counts = live_instance_counts(events, live_pids)
    events = attach_cluster_identity(
        events,
        anchor_pids=anchor_pids,
        instance_counts=instance_counts,
    )

    if cfg.watch_mode and lifecycle_tracker is not None:
        lifecycle_tracker.set_live_product_pids(live_product_pids(events, live_pids))
        watch_events = [e for e in events if is_static_watch_event(e)]
        watch_events = lifecycle_tracker.merge_overlay_holdover(
            watch_events,
            live_pids=live_pids,
        )
        lifecycle = lifecycle_tracker.update(
            watch_events,
            interview_active=interview_active,
        )
        events = [e for e in events if not is_static_watch_event(e)]
        events.extend(lifecycle)

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
        _native_meeting_processes(signatures.interview_processes),
        signatures.process_names,
        signatures.path_substrings,
        signatures.process_tree_roots,
    )


def _scan_network(core, signatures: Signatures) -> list[dict]:
    return core.scan_network(
        signatures.network_domains,
        signatures.allowlist_processes,
        signatures.allowlist_path_substrings,
        _native_meeting_processes(signatures.interview_processes),
    )


def _scan_stealth_relays(
    core,
    signatures: Signatures,
    catalog: TrustedCatalog,
    meeting_processes: list[str] | None = None,
) -> list[dict]:
    return core.scan_stealth_relays(
        signatures.allowlist_processes,
        signatures.allowlist_path_substrings,
        meeting_processes or _native_meeting_processes(signatures.interview_processes),
        catalog.trust_publishers,
        catalog.tier2_publishers,
        catalog.companion_processes,
        catalog.trust_path_prefixes,
        signatures.suspicious_path_prefixes,
        signatures.process_names,
        signatures.path_substrings,
        _relay_process_rules(catalog.processes),
    )


def _relay_process_rules(processes: list[dict]) -> list[str]:
    rules: list[str] = []
    for entry in processes:
        name = str(entry.get("name") or "").strip()
        raw_publishers = entry.get("publishers")
        if raw_publishers is None:
            raw_publishers = [entry.get("publisher")]
        raw_prefixes = entry.get("path_prefixes") or []
        if not name:
            continue
        for publisher in raw_publishers or []:
            publisher_text = str(publisher or "").strip()
            if not publisher_text:
                continue
            for prefix in raw_prefixes:
                prefix_text = str(prefix or "").strip()
                if prefix_text:
                    rules.append(f"{name}\t{publisher_text}\t{prefix_text}")
    return rules


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
