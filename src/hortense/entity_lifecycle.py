from __future__ import annotations

from dataclasses import dataclass, replace

from hortense.models import DetectionEvent

WATCH_LIFECYCLE_CATEGORIES = {
    "process",
    "display_affinity",
    "overlay",
    "stealth_relay",
    "microphone",
    "known_app_anomaly",
}

LOCAL_LIFECYCLE_CATEGORIES = {
    "process",
    "display_affinity",
    "overlay",
    "known_app_anomaly",
}

MEETING_GATED_LIFECYCLE_CATEGORIES = {
    "stealth_relay",
    "microphone",
}

# A relay whose product cluster has any of these is retained: shown regardless of
# meeting state, and cleared only when the port actually stops.
RELAY_RETENTION_CATEGORIES = {
    "process",
    "overlay",
    "display_affinity",
    "known_app_anomaly",
    "microphone",
}

# The acting-like-a-cheat signals. A relay correlated with any of these is threat
# severity; a relay correlated with only known_app_anomaly is informational.
RELAY_THREAT_CATEGORIES = {
    "process",
    "overlay",
    "display_affinity",
    "microphone",
}

APPEAR_POLLS = 1
GONE_POLLS = 2


@dataclass(frozen=True)
class ProductClusterView:
    product_key: str
    display_name: str
    signals: list[str]
    signal_count: int
    severity_counts: dict[str, int]
    anchor_pid: int | None = None
    instance_count: int | None = None
    live_pids: list[int] | None = None
    cluster_confidence: str | None = None
    cluster_classification: str | None = None
    meeting_context: str | None = None


def format_signal_label(fingerprint: str) -> str:
    parts = fingerprint.split("|")
    if "relay" in parts:
        idx = parts.index("relay")
        signal = parts[idx + 1] if len(parts) > idx + 1 else ""
        if signal == "listener":
            return "relay listener"
        if signal == "intranet":
            return "relay peer"
        return "relay"
    if "display_affinity" in parts:
        return "display affinity"
    if "overlay" in parts:
        return "overlay"
    if "microphone" in parts:
        return "microphone"
    if "known_app_anomaly" in parts:
        return "known-app anomaly"
    if "impersonation" in parts:
        return "trusted-app impersonation"
    if "process" in parts:
        return "process"
    return parts[-1].replace("_", " ") if parts else "signal"


def _strongest_value(values: list[str], ranking: dict[str, int]) -> str | None:
    known = [value for value in values if value in ranking]
    if known:
        return max(known, key=lambda value: ranking[value])
    return values[0] if values else None


def _cluster_confidence_from_templates(templates: list[DetectionEvent]) -> str | None:
    values = [
        str(template.metadata.get("cluster_confidence"))
        for template in templates
        if template.metadata.get("cluster_confidence")
    ]
    return _strongest_value(
        values,
        {
            "heuristic": 1,
            "medium": 2,
            "corroborated": 3,
            "strong": 4,
        },
    )


def _cluster_classification_from_templates(templates: list[DetectionEvent]) -> str | None:
    values = [
        str(template.metadata.get("cluster_classification"))
        for template in templates
        if template.metadata.get("cluster_classification")
    ]
    return _strongest_value(
        values,
        {
            "unknown_single_signal": 1,
            "modified_known_app": 2,
            "suspicious_stack": 3,
            "known_cheat": 4,
        },
    )


def _meeting_context_from_templates(templates: list[DetectionEvent]) -> str | None:
    values = [
        str(template.metadata.get("meeting_context"))
        for template in templates
        if template.metadata.get("meeting_context")
    ]
    return _strongest_value(values, {"pre_call": 1, "meeting_active": 2})


def is_static_watch_event(event: DetectionEvent) -> bool:
    if event.category not in WATCH_LIFECYCLE_CATEGORIES:
        return False
    if event.metadata.get("lifecycle") is not None:
        return False
    if event.category == "stealth_relay":
        signal = event.metadata.get("signal")
        return signal in {"listener", "intranet"}
    return True


def signal_fingerprint(event: DetectionEvent) -> str | None:
    product_key = str(event.metadata.get("product_key") or "")
    if not product_key:
        return None

    category = event.category
    if event.metadata.get("impersonation"):
        name = str(event.metadata.get("impersonated_name") or event.process_name or "unknown")
        return f"{product_key}|impersonation|{name.casefold()}"
    if category == "process":
        return f"{product_key}|process"
    if category == "display_affinity":
        return f"{product_key}|display_affinity|{window_signal_identity(event)}"
    if category == "overlay":
        return f"{product_key}|overlay|{window_signal_identity(event)}"
    if category == "microphone":
        return f"{product_key}|microphone"
    if category == "known_app_anomaly":
        reasons = ",".join(str(item) for item in event.metadata.get("anomaly_reasons") or [])
        return f"{product_key}|known_app_anomaly|{reasons.casefold()}"
    if category == "stealth_relay":
        signal = event.metadata.get("signal")
        if signal == "listener":
            port = event.metadata.get("local_port", "?")
            bind_scope = event.metadata.get("bind_scope", "?")
            return f"{product_key}|relay|listener|{port}|{bind_scope}"
        if signal == "intranet":
            remote = str(event.metadata.get("remote_ip", "?")).casefold()
            return f"{product_key}|relay|intranet|{remote}"
    return None


def window_signal_identity(event: DetectionEvent) -> str:
    if event.hwnd is not None:
        return f"hwnd:{event.hwnd}"
    if event.window_title:
        return f"title:{event.window_title.casefold()}"
    if event.pid is not None:
        return f"pid:{event.pid}"
    return "unknown"


class EntityLifecycleTracker:
    def __init__(self) -> None:
        self._active: set[str] = set()
        self._seen_gone: set[str] = set()
        self._templates: dict[str, DetectionEvent] = {}
        self._missing_polls: dict[str, int] = {}
        self._product_signals: dict[str, set[str]] = {}
        self._product_names: dict[str, str] = {}
        self._last_product_signals: dict[str, set[str]] = {}
        self._product_pids_seen: dict[str, set[int]] = {}
        self._product_paths_seen: dict[str, set[str]] = {}
        self._live_product_pids: dict[str, list[int]] = {}
        self._overlay_holdover: dict[str, tuple[DetectionEvent, int]] = {}
        self._event_sequence = 0
        self.interview_active = False
        self.meeting_app_count = 0
        self.meeting_app_names: list[str] = []
        self.raw_meeting_app_names: list[str] = []

    def reset(self) -> None:
        self._active.clear()
        self._seen_gone.clear()
        self._templates.clear()
        self._missing_polls.clear()
        self._product_signals.clear()
        self._product_names.clear()
        self._last_product_signals.clear()
        self._product_pids_seen.clear()
        self._product_paths_seen.clear()
        self._live_product_pids.clear()
        self._overlay_holdover.clear()
        self.interview_active = False
        self.meeting_app_count = 0
        self.meeting_app_names = []
        self.raw_meeting_app_names = []

    def _next_sequence(self) -> int:
        self._event_sequence += 1
        return self._event_sequence

    def flush_all_gone(self) -> list[DetectionEvent]:
        lifecycle: list[DetectionEvent] = []
        for key in sorted(self._active):
            template = self._templates.get(key)
            if template is None:
                continue
            lifecycle.append(self._signal_event(template, key, "gone"))
            self._seen_gone.add(key)
        self._active.clear()
        self._missing_polls.clear()
        self._overlay_holdover.clear()
        return lifecycle

    def set_live_product_pids(self, live_by_product: dict[str, list[int]]) -> None:
        self._live_product_pids = {
            product_key: sorted(pids)
            for product_key, pids in live_by_product.items()
            if pids
        }

    def merge_overlay_holdover(
        self,
        watch_events: list[DetectionEvent],
        *,
        live_pids: set[int],
    ) -> list[DetectionEvent]:
        current_overlays: dict[str, DetectionEvent] = {}
        for event in watch_events:
            if event.category != "overlay":
                continue
            key = signal_fingerprint(event)
            if key is None:
                continue
            if event.pid is not None and event.pid not in live_pids:
                self._overlay_holdover.pop(key, None)
                continue
            current_overlays[key] = event
            self._overlay_holdover[key] = (event, 0)

        merged = list(watch_events)
        merged_keys = {
            key for event in watch_events if (key := signal_fingerprint(event)) is not None
        }
        expired: list[str] = []

        for key, (held_event, misses) in list(self._overlay_holdover.items()):
            if key in current_overlays:
                continue
            if held_event.pid is not None and held_event.pid not in live_pids:
                expired.append(key)
                continue
            misses += 1
            if misses > GONE_POLLS:
                expired.append(key)
                continue
            self._overlay_holdover[key] = (held_event, misses)
            if key not in merged_keys:
                merged.append(held_event)
                merged_keys.add(key)

        for key in expired:
            self._overlay_holdover.pop(key, None)
        return merged

    def _clear_overlay_holdover_for_product(self, product_key: str) -> None:
        for key, (event, _) in list(self._overlay_holdover.items()):
            if str(event.metadata.get("product_key") or "") == product_key:
                self._overlay_holdover.pop(key, None)

    def active_snapshot(self) -> list[ProductClusterView]:
        self._rebuild_product_signals()
        views: list[ProductClusterView] = []
        for product_key, keys in sorted(self._product_signals.items()):
            labels = sorted({format_signal_label(key) for key in keys})
            severity_counts: dict[str, int] = {}
            anchor_pid: int | None = None
            templates: list[DetectionEvent] = []
            for key in sorted(keys):
                template = self._templates.get(key)
                if template is None:
                    continue
                templates.append(template)
                severity_counts[template.severity] = severity_counts.get(template.severity, 0) + 1
                anchor = template.metadata.get("anchor_pid")
                if anchor_pid is None and isinstance(anchor, int):
                    anchor_pid = anchor
                elif anchor_pid is None and template.pid is not None:
                    anchor_pid = template.pid
            live_pids = self._live_product_pids.get(product_key, [])
            instance_count = len(live_pids) if len(live_pids) > 1 else None
            views.append(
                ProductClusterView(
                    product_key=product_key,
                    display_name=self._product_names.get(product_key, "unknown"),
                    signals=labels,
                    signal_count=len(keys),
                    severity_counts=severity_counts,
                    anchor_pid=anchor_pid,
                    instance_count=instance_count,
                    live_pids=live_pids if len(live_pids) > 1 else None,
                    cluster_confidence=_cluster_confidence_from_templates(templates),
                    cluster_classification=_cluster_classification_from_templates(templates),
                    meeting_context=_meeting_context_from_templates(templates),
                )
            )
        return views

    def update(
        self,
        watch_events: list[DetectionEvent],
        *,
        interview_active: bool,
    ) -> list[DetectionEvent]:
        self.interview_active = interview_active

        current: set[str] = set()
        for event in watch_events:
            key = signal_fingerprint(event)
            if key is None:
                continue
            current.add(key)
            self._templates[key] = event
            self._missing_polls.pop(key, None)
            display = str(
                event.metadata.get("display_name")
                or event.process_name
                or "unknown"
            )
            product_key = str(event.metadata.get("product_key") or "unknown")
            self._product_names[product_key] = display
            if product_key != "unknown":
                if event.pid is not None:
                    self._product_pids_seen.setdefault(product_key, set()).add(event.pid)
                if event.process_path:
                    self._product_paths_seen.setdefault(product_key, set()).add(
                        event.process_path
                    )

        lifecycle: list[DetectionEvent] = []

        for key in sorted(current - self._active):
            template = self._templates[key]
            transition = "returned" if key in self._seen_gone else "appeared"
            lifecycle.append(self._signal_event(template, key, transition))

        vanished = (self._active | set(self._missing_polls.keys())) - current

        # Tier-aware pause: when a call ends, a bare call-context signal (a lone
        # relay or a mic with nothing corroborating it) is paused quietly, not
        # cleared. Pausing emits no gone event and never marks the key as seen-gone,
        # so it can silently reappear when the call resumes. Retained relays (their
        # product cluster still shows an anomaly or a threat signal) fall through to
        # the normal gone path, so they only clear when the port actually stops.
        # Retention is judged against signals that are still live: seen this poll,
        # active last poll, or inside the gone debounce grace. That window matters
        # when a modified app closes: its anomaly and its relay vanish together (and
        # ride out the debounce together), and we want the relay to clear as a real
        # stop rather than pause, because the port genuinely went away.
        grace_keys = {
            key for key, misses in self._missing_polls.items() if misses < GONE_POLLS
        }
        retention_scope = current | self._active | grace_keys
        paused_keys: set[str] = set()
        paused_products: set[str] = set()
        if not interview_active:
            for key in vanished:
                template = self._templates.get(key)
                if template is None:
                    continue
                category = template.category
                if category not in MEETING_GATED_LIFECYCLE_CATEGORIES:
                    continue
                if category == "microphone":
                    product_key = str(template.metadata.get("product_key") or "")
                    if not self._cluster_has_retention_sibling(
                        product_key,
                        key,
                        retention_scope,
                        retention_categories=RELAY_RETENTION_CATEGORIES | {"stealth_relay"},
                    ):
                        paused_keys.add(key)
                elif category == "stealth_relay":
                    product_key = str(template.metadata.get("product_key") or "")
                    if not self._cluster_has_retention_sibling(
                        product_key, key, retention_scope
                    ):
                        paused_keys.add(key)

        for key in paused_keys:
            template = self._templates.get(key)
            if template is not None:
                paused_products.add(str(template.metadata.get("product_key") or ""))
            self._missing_polls.pop(key, None)

        pending_gone: set[str] = set()
        missing_candidates = vanished - paused_keys
        for key in sorted(missing_candidates):
            misses = self._missing_polls.get(key, 0) + 1
            self._missing_polls[key] = misses
            if misses >= GONE_POLLS:
                pending_gone.add(key)

        for key in sorted(pending_gone):
            template = self._templates.get(key)
            if template is None:
                continue
            lifecycle.append(self._signal_event(template, key, "gone"))
            self._seen_gone.add(key)
            self._missing_polls.pop(key, None)

        grace_keys = {
            key for key, misses in self._missing_polls.items() if misses < GONE_POLLS
        }
        self._active = current | grace_keys
        self._rebuild_product_signals()

        # A cluster that empties solely because its bare relays were paused must not
        # emit a fake "session ended" clear. Pre-set its remembered signal set to
        # empty so the rollup treats it as already reconciled.
        for product_key in paused_products:
            if product_key and not self._product_signals.get(product_key):
                self._last_product_signals[product_key] = set()

        lifecycle.extend(self._product_rollup_events())
        return self._clean_same_poll_full_clears(lifecycle)

    def _cluster_has_retention_sibling(
        self,
        product_key: str,
        exclude_key: str,
        current: set[str],
        *,
        retention_categories: set[str] = RELAY_RETENTION_CATEGORIES,
    ) -> bool:
        if not product_key:
            return False
        for key in current:
            if key == exclude_key:
                continue
            template = self._templates.get(key)
            if template is None:
                continue
            if str(template.metadata.get("product_key") or "") != product_key:
                continue
            if template.category in retention_categories:
                return True
        return False

    def _rebuild_product_signals(self) -> None:
        self._product_signals.clear()
        live_keys = set(self._active)
        for key, misses in self._missing_polls.items():
            if misses < GONE_POLLS:
                live_keys.add(key)
        for key in live_keys:
            template = self._templates.get(key)
            if template is None:
                continue
            product_key = str(template.metadata.get("product_key") or "unknown")
            self._product_signals.setdefault(product_key, set()).add(key)

    def _product_rollup_events(self, *, force_all_cleared: bool = False) -> list[DetectionEvent]:
        rollup: list[DetectionEvent] = []
        product_keys = set(self._last_product_signals) | set(self._product_signals)
        for product_key in sorted(product_keys):
            previous = self._last_product_signals.get(product_key, set())
            current = self._product_signals.get(product_key, set())

            if force_all_cleared:
                if not previous:
                    self._last_product_signals[product_key] = set()
                    continue
                cleared = sorted(previous)
            elif previous and not current:
                cleared = sorted(previous)
            else:
                self._last_product_signals[product_key] = set(current)
                continue

            display = self._product_names.get(product_key, "unknown")
            session_pids = sorted(self._product_pids_seen.get(product_key, set()))
            paths_seen = self._product_paths_seen.get(product_key, set())
            best_path = max(paths_seen, key=len) if paths_seen else None
            rollup_pid = session_pids[0] if len(session_pids) == 1 else None
            rollup_metadata: dict = {
                "lifecycle": "cleared",
                "lifecycle_scope": "complete",
                "product_key": product_key,
                "display_name": display,
                "signals_cleared": cleared,
            }
            if session_pids:
                rollup_metadata["pids_cleared"] = session_pids
            rollup.append(
                DetectionEvent(
                    id=f"product:cleared:{self._next_sequence()}:{product_key}",
                    severity="cleared",
                    category="product_session",
                    title=f"Session ended - {display} (all signals cleared)",
                    detail="All corroborating signals for this product cluster have cleared.",
                    process_name=display,
                    process_path=best_path,
                    pid=rollup_pid,
                    metadata=rollup_metadata,
                )
            )
            self._last_product_signals[product_key] = set(current)
            self._product_pids_seen.pop(product_key, None)
            self._product_paths_seen.pop(product_key, None)
            self._clear_overlay_holdover_for_product(product_key)
        return rollup

    def _clean_same_poll_full_clears(
        self,
        lifecycle: list[DetectionEvent],
    ) -> list[DetectionEvent]:
        cleared_products = {
            str(event.metadata.get("product_key") or "")
            for event in lifecycle
            if event.metadata.get("lifecycle") == "cleared"
            and str(event.metadata.get("product_key") or "")
        }
        if not cleared_products:
            return lifecycle

        cleaned: list[DetectionEvent] = []
        for event in lifecycle:
            product_key = str(event.metadata.get("product_key") or "")
            if (
                event.metadata.get("lifecycle") == "gone"
                and product_key in cleared_products
            ):
                metadata = dict(event.metadata)
                metadata.pop("still_active", None)
                metadata.pop("active_count", None)
                if metadata.get("lifecycle_scope") == "partial":
                    metadata["lifecycle_scope"] = "cluster_clearing"
                else:
                    metadata.setdefault("lifecycle_scope", "cluster_clearing")
                cleaned.append(replace(event, metadata=metadata))
                continue
            cleaned.append(event)
        return cleaned

    def _signal_event(
        self,
        template: DetectionEvent,
        key: str,
        transition: str,
    ) -> DetectionEvent:
        display = str(
            template.metadata.get("display_name")
            or template.process_name
            or "unknown"
        )
        signal_label = format_signal_label(key)
        titles = {
            "appeared": f"{template.category.replace('_', ' ').title()} appeared - {display}",
            "gone": f"{template.category.replace('_', ' ').title()} layer cleared - {display}",
            "returned": f"{template.category.replace('_', ' ').title()} returned - {display}",
        }
        # appeared/returned inherit the underlying signal's severity so the relay
        # tiers (low/medium anomaly-informational, high threat) show honestly in the
        # watch feed and the JSONL. A clearing signal is always low-noise.
        severities = {
            "appeared": template.severity,
            "gone": "low",
            "returned": template.severity,
        }
        metadata = dict(template.metadata)
        if template.category != "process":
            metadata.pop("instance_count", None)
        metadata["lifecycle"] = transition
        metadata["lifecycle_sequence"] = self._next_sequence()
        metadata["signal_fingerprint"] = key
        metadata["signal_cleared"] = signal_label
        product_key = str(metadata.get("product_key") or "")
        if product_key and template.category == "process":
            pids_seen = sorted(self._product_pids_seen.get(product_key, set()))
            if len(pids_seen) > 1:
                metadata["pids_seen"] = pids_seen
            live_count = metadata.get("instance_count")
            if isinstance(live_count, int) and live_count > 1:
                anchor = metadata.get("anchor_pid")
                main_pid = anchor if isinstance(anchor, int) else template.pid
                if main_pid is not None:
                    metadata["anchor_pid"] = main_pid
        if product_key and transition == "gone":
            active = {
                k
                for k in self._product_signals.get(product_key, set())
                if k != key
            }
            if active:
                metadata["lifecycle_scope"] = "partial"
                metadata["still_active"] = sorted(active)
                metadata["active_count"] = len(active)
        return replace(
            template,
            id=f"lifecycle:{transition}:{metadata['lifecycle_sequence']}:{key}",
            severity=severities[transition],
            title=titles[transition],
            metadata=metadata,
        )


# Backward-compatible exports for relay tests during migration.
def relay_fingerprint(event: DetectionEvent) -> str | None:
    return signal_fingerprint(event)


def is_static_listener_event(event: DetectionEvent) -> bool:
    return (
        event.category == "stealth_relay"
        and event.metadata.get("signal") == "listener"
        and event.metadata.get("lifecycle") is None
    )


class RelayLifecycleTracker(EntityLifecycleTracker):
    """Deprecated alias; use EntityLifecycleTracker."""

    def update(
        self,
        listener_events: list[DetectionEvent],
        *,
        interview_active: bool,
    ) -> list[DetectionEvent]:
        return super().update(listener_events, interview_active=interview_active)
