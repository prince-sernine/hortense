from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PARENT_WALK_MAX = 32


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


def display_name(path: str | None, process_name: str | None) -> str:
    if process_name:
        return process_name
    if path:
        return Path(path).name
    return "unknown"
