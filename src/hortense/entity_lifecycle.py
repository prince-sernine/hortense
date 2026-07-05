from __future__ import annotations

import unicodedata
from dataclasses import replace

from hortense.models import DetectionEvent

WATCH_LIFECYCLE_CATEGORIES = {
    "process",
    "display_affinity",
    "overlay",
    "stealth_relay",
    "microphone",
}

APPEAR_POLLS = 1
GONE_POLLS = 2


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
    if category == "process":
        return f"{product_key}|process"
    if category == "display_affinity":
        title = (event.window_title or "unknown").casefold()
        return f"{product_key}|display_affinity|{title}"
    if category == "overlay":
        title = (event.window_title or "unknown").casefold()
        return f"{product_key}|overlay|{title}"
    if category == "microphone":
        return f"{product_key}|microphone"
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


class EntityLifecycleTracker:
    def __init__(self) -> None:
        self._active: set[str] = set()
        self._seen_gone: set[str] = set()
        self._templates: dict[str, DetectionEvent] = {}
        self._missing_polls: dict[str, int] = {}
        self._product_signals: dict[str, set[str]] = {}
        self._product_names: dict[str, str] = {}
        self._last_product_signals: dict[str, set[str]] = {}

    def reset(self) -> None:
        self._active.clear()
        self._seen_gone.clear()
        self._templates.clear()
        self._missing_polls.clear()
        self._product_signals.clear()
        self._product_names.clear()
        self._last_product_signals.clear()

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
        return lifecycle

    def update(
        self,
        watch_events: list[DetectionEvent],
        *,
        interview_active: bool,
    ) -> list[DetectionEvent]:
        if not interview_active:
            flushed = self.flush_all_gone()
            self._rebuild_product_signals()
            rollup = self._product_rollup_events(force_all_cleared=True)
            self.reset()
            return flushed + rollup

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

        lifecycle: list[DetectionEvent] = []

        for key in sorted(current - self._active):
            template = self._templates[key]
            transition = "returned" if key in self._seen_gone else "appeared"
            lifecycle.append(self._signal_event(template, key, transition))

        pending_gone: set[str] = set()
        missing_candidates = (self._active | set(self._missing_polls.keys())) - current
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

        self._active = current
        self._rebuild_product_signals()
        lifecycle.extend(self._product_rollup_events())
        return lifecycle

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
            rollup.append(
                DetectionEvent(
                    id=f"product:cleared:{product_key}",
                    severity="cleared",
                    category="product_session",
                    title=f"Session ended — {display} (all signals cleared)",
                    detail="All corroborating signals for this product cluster have cleared.",
                    process_name=display,
                    metadata={
                        "lifecycle": "cleared",
                        "lifecycle_scope": "complete",
                        "product_key": product_key,
                        "display_name": display,
                        "signals_cleared": cleared,
                    },
                )
            )
            self._last_product_signals[product_key] = set(current)
        return rollup

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
        signal_label = key.split("|")[-1] if "|" in key else template.category
        titles = {
            "appeared": f"{template.category.replace('_', ' ').title()} appeared — {display}",
            "gone": f"{template.category.replace('_', ' ').title()} layer cleared — {display}",
            "returned": f"{template.category.replace('_', ' ').title()} returned — {display}",
        }
        severities = {
            "appeared": "medium",
            "gone": "low",
            "returned": "medium",
        }
        metadata = dict(template.metadata)
        metadata["lifecycle"] = transition
        metadata["signal_fingerprint"] = key
        metadata["signal_cleared"] = signal_label
        product_key = str(metadata.get("product_key") or "")
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
            id=f"lifecycle:{transition}:{key}",
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
