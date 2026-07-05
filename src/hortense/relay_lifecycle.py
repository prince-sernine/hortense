from __future__ import annotations

from dataclasses import replace

from hortense.models import DetectionEvent


def relay_fingerprint(event: DetectionEvent) -> str | None:
    if event.category != "stealth_relay":
        return None
    if event.metadata.get("signal") != "listener":
        return None
    path = (event.process_path or event.process_name or "").casefold().replace("/", "\\")
    port = event.metadata.get("local_port", "?")
    bind_scope = event.metadata.get("bind_scope", "?")
    name = (event.process_name or "unknown").casefold()
    return f"{name}|{port}|{bind_scope}|{path}"


def is_static_listener_event(event: DetectionEvent) -> bool:
    return (
        event.category == "stealth_relay"
        and event.metadata.get("signal") == "listener"
        and event.metadata.get("lifecycle") is None
    )


class RelayLifecycleTracker:
    def __init__(self) -> None:
        self._active: set[str] = set()
        self._seen_gone: set[str] = set()
        self._templates: dict[str, DetectionEvent] = {}

    def reset(self) -> None:
        self._active.clear()
        self._seen_gone.clear()
        self._templates.clear()

    def update(
        self,
        listener_events: list[DetectionEvent],
        *,
        interview_active: bool,
    ) -> list[DetectionEvent]:
        if not interview_active:
            self.reset()
            return []

        current: set[str] = set()
        for event in listener_events:
            key = relay_fingerprint(event)
            if key is None:
                continue
            current.add(key)
            self._templates[key] = event

        lifecycle: list[DetectionEvent] = []

        for key in sorted(current - self._active):
            template = self._templates[key]
            if key in self._seen_gone:
                lifecycle.append(self._lifecycle_event(template, key, "returned"))
            else:
                lifecycle.append(self._lifecycle_event(template, key, "appeared"))

        for key in sorted(self._active - current):
            template = self._templates.get(key)
            if template is None:
                continue
            lifecycle.append(self._lifecycle_event(template, key, "gone"))
            self._seen_gone.add(key)

        self._active = current
        return lifecycle

    def _lifecycle_event(
        self,
        template: DetectionEvent,
        key: str,
        transition: str,
    ) -> DetectionEvent:
        titles = {
            "appeared": "Stealth relay listener appeared during interview session",
            "gone": "Stealth relay listener no longer active",
            "returned": "Stealth relay listener returned during interview session",
        }
        severities = {
            "appeared": "medium",
            "gone": "low",
            "returned": "medium",
        }
        metadata = dict(template.metadata)
        metadata["lifecycle"] = transition
        metadata["relay_fingerprint"] = key
        return replace(
            template,
            id=f"stealth_relay:lifecycle:{transition}:{key}",
            severity=severities[transition],
            title=titles[transition],
            metadata=metadata,
        )
