from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class DetectionEvent:
    id: str
    severity: str
    category: str
    title: str
    detail: str
    process_name: str | None = None
    process_path: str | None = None
    pid: int | None = None
    hwnd: int | None = None
    window_title: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> DetectionEvent:
        metadata = raw.get("metadata") or {}
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {"raw": metadata}

        return cls(
            id=str(raw["id"]),
            severity=str(raw["severity"]),
            category=str(raw["category"]),
            title=str(raw["title"]),
            detail=str(raw["detail"]),
            process_name=raw.get("process_name"),
            process_path=raw.get("process_path"),
            pid=raw.get("pid"),
            hwnd=raw.get("hwnd"),
            window_title=raw.get("window_title"),
            metadata=dict(metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def score(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "cleared": 0}.get(self.severity, 0)
