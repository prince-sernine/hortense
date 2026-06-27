from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable, TextIO

from hortense.models import DetectionEvent


class JsonReporter:
    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream or sys.stdout

    def emit_many(self, events: Iterable[DetectionEvent]) -> None:
        payload = [event.to_dict() for event in events]
        json.dump(payload, self.stream, indent=2)
        self.stream.write("\n")
        self.stream.flush()


class JsonlReporter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: DetectionEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False))
            handle.write("\n")

    def emit_many(self, events: Iterable[DetectionEvent]) -> None:
        for event in events:
            self.emit(event)
