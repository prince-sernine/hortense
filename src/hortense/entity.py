from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
import unicodedata
from typing import Any

from hortense.models import DetectionEvent


PARENT_WALK_MAX = 32

_EXPLICIT_IGNORABLE = {
    "\u2800",  # braille blank (Parakeet field case)
    "\ufeff",  # BOM / zero-width no-break space
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u00ad",  # soft hyphen
    "\u2060",  # word joiner
}


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    parent_pid: int
    exe: str
    path: str | None


def normalize_path(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").casefold()


def install_root(path: str | None, tree_roots: list[str] | None = None) -> str:
    normalized = normalize_path(path)
    if not normalized:
        return ""

    roots = [normalize_path(r) for r in (tree_roots or []) if r]
    for root in roots:
        if root in normalized:
            idx = normalized.find(root)
            end = idx + len(root.rstrip("\\"))
            return normalized[:end]

    parent = str(Path(normalized).parent)
    if parent in ("", ".", normalized):
        return normalized
    return parent


def build_process_index(
    snapshot: list[dict],
) -> tuple[dict[int, ProcessRecord], set[int]]:
    by_pid: dict[int, ProcessRecord] = {}
    live_pids: set[int] = set()
    for row in snapshot:
        pid = int(row["pid"])
        live_pids.add(pid)
        by_pid[pid] = ProcessRecord(
            pid=pid,
            parent_pid=int(row.get("parent_pid") or 0),
            exe=str(row.get("exe") or ""),
            path=row.get("path"),
        )
    return by_pid, live_pids


def parent_chain(
    pid: int | None,
    by_pid: dict[int, ProcessRecord],
    *,
    max_depth: int = PARENT_WALK_MAX,
) -> list[int]:
    if pid is None:
        return []
    chain: list[int] = []
    seen: set[int] = set()
    current = pid
    while current and current not in seen and len(chain) < max_depth:
        seen.add(current)
        chain.append(current)
        record = by_pid.get(current)
        if record is None:
            break
        current = record.parent_pid
    return chain


def product_key(
    pid: int | None,
    path: str | None,
    *,
    by_pid: dict[int, ProcessRecord],
    tree_roots: list[str] | None = None,
    live_pids: set[int] | None = None,
) -> str:
    normalized_path = normalize_path(path)
    if not normalized_path and pid is not None:
        record = by_pid.get(pid)
        if record and record.path:
            normalized_path = normalize_path(record.path)

    root = install_root(normalized_path or None, tree_roots)
    if root:
        return root

    for ancestor in parent_chain(pid, by_pid):
        record = by_pid.get(ancestor)
        if not record:
            continue
        ancestor_root = install_root(record.path, tree_roots)
        if ancestor_root:
            return ancestor_root

    if pid is not None:
        return f"pid:{pid}"
    return "unknown"


def pick_anchor_pid(
    candidates: set[int],
    by_pid: dict[int, ProcessRecord],
) -> int | None:
    if not candidates:
        return None
    roots = [
        pid
        for pid in candidates
        if (record := by_pid.get(pid)) is not None and record.parent_pid not in candidates
    ]
    if roots:
        return min(roots)
    return min(candidates)


def compute_anchor_pids(
    events: list[DetectionEvent],
    by_pid: dict[int, ProcessRecord],
) -> dict[str, int]:
    process_pids: dict[str, set[int]] = defaultdict(set)
    relay_pids: dict[str, int] = {}
    window_pids: dict[str, int] = {}

    for event in events:
        pk = str(event.metadata.get("product_key") or "")
        if not pk or pk == "unknown" or pk.startswith("pid:"):
            continue
        if event.pid is None:
            continue
        if event.category == "process":
            process_pids[pk].add(event.pid)
        elif event.category == "stealth_relay" and event.metadata.get("signal") == "listener":
            relay_pids[pk] = event.pid
        elif event.category in {"overlay", "display_affinity"}:
            window_pids.setdefault(pk, event.pid)

    anchors: dict[str, int] = {}
    product_keys = set(process_pids) | set(relay_pids) | set(window_pids)
    for pk in product_keys:
        if pk in relay_pids:
            anchors[pk] = relay_pids[pk]
        elif pk in window_pids:
            anchors[pk] = window_pids[pk]
        else:
            picked = pick_anchor_pid(process_pids[pk], by_pid)
            if picked is not None:
                anchors[pk] = picked
    return anchors


def live_product_pids(
    events: list[DetectionEvent],
    live_pids: set[int],
) -> dict[str, list[int]]:
    grouped: dict[str, set[int]] = defaultdict(set)
    for event in events:
        if event.category != "process" or event.pid is None:
            continue
        if event.pid not in live_pids:
            continue
        pk = str(event.metadata.get("product_key") or "")
        if not pk or pk.startswith("pid:"):
            continue
        grouped[pk].add(event.pid)
    return {pk: sorted(pids) for pk, pids in grouped.items()}


def live_instance_counts(
    events: list[DetectionEvent],
    live_pids: set[int],
) -> dict[str, int]:
    grouped = live_product_pids(events, live_pids)
    return {pk: len(pids) for pk, pids in grouped.items() if len(pids) > 1}


def attach_cluster_identity(
    events: list[DetectionEvent],
    *,
    anchor_pids: dict[str, int],
    instance_counts: dict[str, int],
) -> list[DetectionEvent]:
    enriched: list[DetectionEvent] = []
    for event in events:
        pk = str(event.metadata.get("product_key") or "")
        metadata = dict(event.metadata)
        anchor = anchor_pids.get(pk)
        if anchor is not None:
            metadata["anchor_pid"] = anchor
        if event.category == "process":
            count = instance_counts.get(pk)
            if count is not None and count > 1:
                metadata["instance_count"] = count
        enriched.append(replace(event, metadata=metadata))
    return enriched


def prefer_process_event(
    current: DetectionEvent,
    candidate: DetectionEvent,
    anchor_pid: int | None,
) -> DetectionEvent:
    if anchor_pid is not None:
        current_anchor = current.pid == anchor_pid
        candidate_anchor = candidate.pid == anchor_pid
        if current_anchor != candidate_anchor:
            return current if current_anchor else candidate
    if candidate.score != current.score:
        return candidate if candidate.score > current.score else current
    return candidate if (candidate.pid or 0) < (current.pid or 0) else current


def _is_ignorable_char(ch: str) -> bool:
    if ch in _EXPLICIT_IGNORABLE:
        return True
    if ch.isspace():
        return True
    category = unicodedata.category(ch)
    return category in {"Cf", "Zs", "Zl", "Zp"}


def _stem_and_suffix(name: str) -> tuple[str, str]:
    suffix = Path(name).suffix
    if suffix:
        return name[: -len(suffix)], suffix
    return name, ""


def _strip_ignorable(stem: str) -> tuple[str, list[str]]:
    kept: list[str] = []
    removed: list[str] = []
    for ch in stem:
        if _is_ignorable_char(ch):
            removed.append(f"U+{ord(ch):04X}")
        else:
            kept.append(ch)
    return "".join(kept), removed


def is_obfuscated_executable_name(name: str) -> bool:
    if not name:
        return False
    stem, _suffix = _stem_and_suffix(name)
    stripped, _removed = _strip_ignorable(stem)
    if not stripped:
        return True
    if all(ch in ".-_" for ch in stripped):
        return True
    visible = sum(1 for ch in stripped if ch.isalnum())
    return visible == 0


def format_executable_label(
    path: str | None,
    process_name: str | None,
) -> tuple[str, dict[str, Any]]:
    raw = process_name or (Path(path).name if path else "") or "unknown"
    path_name = Path(path).name if path else ""
    candidates = [item for item in {raw, path_name} if item]
    if not any(is_obfuscated_executable_name(item) for item in candidates):
        return raw, {}

    folder = Path(path).parent.name if path else "unknown"
    label_source = raw if is_obfuscated_executable_name(raw) else path_name
    stem, suffix = _stem_and_suffix(label_source)
    _stripped, removed = _strip_ignorable(stem)
    unique: list[str] = []
    for codepoint in removed:
        if codepoint not in unique:
            unique.append(codepoint)
    unique = unique[:3]
    codepoint_label = "+".join(unique) if unique else "U+????"
    label = f"{folder} [{codepoint_label}]{suffix or '.exe'}"
    return label, {
        "raw_process_name": raw,
        "obfuscated_executable": True,
        "obfuscation_codepoints": unique,
    }


def display_name(path: str | None, process_name: str | None) -> str:
    label, _extra = format_executable_label(path, process_name)
    return label


def event_display_name(event: DetectionEvent) -> str:
    return str(
        event.metadata.get("display_name")
        or event.process_name
        or "unknown"
    )


def format_pid_list(
    pids: list[int],
    *,
    cap: int = 4,
    max_width: int = 72,
    prefix: str = "pids: ",
) -> str:
    if not pids:
        return ""
    visible = list(pids[:cap])
    while visible:
        line = prefix + ", ".join(str(item) for item in visible)
        overflow = len(pids) - len(visible)
        if overflow > 0:
            line = f"{line} +{overflow} more"
        if len(line) <= max_width or len(visible) == 1:
            return line
        visible.pop()
    return prefix + str(pids[0])


def format_process_identity(event: DetectionEvent) -> str | None:
    display = event_display_name(event)
    pids_cleared = event.metadata.get("pids_cleared")
    if isinstance(pids_cleared, list) and pids_cleared:
        if len(pids_cleared) == 1:
            return f"process: {display} (pid={pids_cleared[0]})"
        joined = ", ".join(str(item) for item in pids_cleared)
        return f"process: {display} (pids={joined})"

    if event.category == "product_session":
        if event.pid is not None:
            return f"process: {display} (pid={event.pid})"
        return None

    if not (event.process_name or event.metadata.get("display_name")):
        return None

    lifecycle = event.metadata.get("lifecycle")
    if lifecycle in {"appeared", "gone", "returned"}:
        if event.pid is not None:
            return f"process: {display} (pid={event.pid})"
        return None

    if event.category != "process":
        if event.pid is not None:
            return f"process: {display} (pid={event.pid})"
        return None

    anchor = event.metadata.get("anchor_pid")
    main_pid = anchor if isinstance(anchor, int) else event.pid
    instance_count = event.metadata.get("instance_count")
    if isinstance(instance_count, int) and instance_count > 1 and main_pid is not None:
        return (
            f"process: {display} (main pid {main_pid}, "
            f"{instance_count} live processes)"
        )

    if main_pid is not None:
        return f"process: {display} (pid={main_pid})"
    return None


def render_detail_line(event: DetectionEvent) -> str:
    detail = event.detail
    if not event.metadata.get("obfuscated_executable"):
        return detail
    raw = str(event.metadata.get("raw_process_name") or "")
    display = str(event.metadata.get("display_name") or "")
    if raw and display and raw in detail:
        return detail.replace(raw, display, 1)
    return detail
