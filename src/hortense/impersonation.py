from __future__ import annotations

import unicodedata

from hortense.models import DetectionEvent


def _normalize_name(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold().strip()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


_HOMOGLYPHS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "і": "i",
        "о": "o",
        "а": "a",
        "е": "e",
    }
)


def _squash_homoglyphs(name: str) -> str:
    return _normalize_name(name).translate(_HOMOGLYPHS)


def catalog_process_names(catalog_processes: list[dict]) -> list[str]:
    names: list[str] = []
    for entry in catalog_processes:
        name = str(entry.get("name", "")).strip()
        if name:
            names.append(name)
    return names


def is_typosquat(candidate: str, canonical: str) -> bool:
    cand = _squash_homoglyphs(candidate)
    canon = _squash_homoglyphs(canonical)
    if not cand or not canon or cand == canon:
        return False
    if len(canon) < 8:
        return False
    return _levenshtein(cand, canon) <= 2


def impersonation_events(
    events: list[DetectionEvent],
    catalog_processes: list[dict],
) -> list[DetectionEvent]:
    if not catalog_processes:
        return list(events)

    upgraded: list[DetectionEvent] = []
    for event in events:
        if event.category not in {"process", "stealth_relay"}:
            upgraded.append(event)
            continue
        name = event.process_name or ""
        if not name:
            upgraded.append(event)
            continue

        hit = False
        for entry in catalog_processes:
            canonical = str(entry.get("name", ""))
            if not canonical or not is_typosquat(name, canonical):
                continue
            expected_pub = str(entry.get("publisher", "")).casefold()
            actual_pub = str(event.metadata.get("publisher") or "").casefold()
            if expected_pub and actual_pub and expected_pub in actual_pub:
                continue
            hit = True
            break

        if not hit:
            upgraded.append(event)
            continue

        metadata = dict(event.metadata)
        metadata["impersonation"] = True
        metadata["impersonated_name"] = canonical
        metadata["confidence"] = "strong"
        upgraded.append(
            DetectionEvent(
                id=f"impersonation:{event.id}",
                severity="high",
                category=event.category,
                title="Possible trusted-app impersonation (name resembles catalog process)",
                detail=event.detail,
                process_name=event.process_name,
                process_path=event.process_path,
                pid=event.pid,
                hwnd=event.hwnd,
                window_title=event.window_title,
                metadata=metadata,
            )
        )
    return upgraded
