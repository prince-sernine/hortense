from __future__ import annotations

from hortense.entity import (
    build_process_index,
    compute_anchor_pids,
    format_executable_label,
    format_process_identity,
    is_obfuscated_executable_name,
    pick_anchor_pid,
    prefer_process_event,
    product_key,
    render_detail_line,
)
from hortense.models import DetectionEvent


def test_product_key_shared_across_parent_and_child() -> None:
    snapshot = [
        {"pid": 100, "parent_pid": 0, "exe": "InterviewMan.exe", "path": r"C:\Apps\InterviewMan\InterviewMan.exe"},
        {"pid": 200, "parent_pid": 100, "exe": "helper.exe", "path": r"C:\Apps\InterviewMan\helper.exe"},
    ]
    by_pid, live = build_process_index(snapshot)
    parent_key = product_key(100, r"C:\Apps\InterviewMan\InterviewMan.exe", by_pid=by_pid, live_pids=live)
    child_key = product_key(200, r"C:\Apps\InterviewMan\helper.exe", by_pid=by_pid, live_pids=live)
    assert parent_key == child_key


def test_braille_blank_exe_is_obfuscated() -> None:
    assert is_obfuscated_executable_name("\u2800.exe")


def test_normal_exe_is_not_obfuscated() -> None:
    assert not is_obfuscated_executable_name("Cluely.exe")
    assert not is_obfuscated_executable_name("pmodule.exe")


def test_cjk_exe_is_not_obfuscated() -> None:
    assert not is_obfuscated_executable_name("\u5fae\u4fe1.exe")


def test_format_executable_label_for_parakeet_style_path() -> None:
    path = r"C:\Users\me\AppData\Local\Programs\parakeetai-desktop\⠀.exe"
    label, meta = format_executable_label(path, "\u2800.exe")
    assert label == "parakeetai-desktop [U+2800].exe"
    assert meta["obfuscated_executable"] is True
    assert meta["raw_process_name"] == "\u2800.exe"
    assert meta["obfuscation_codepoints"] == ["U+2800"]


def test_format_executable_label_zero_width_only_stem() -> None:
    name = "\u200b.exe"
    label, meta = format_executable_label(r"C:\Apps\Evil\payload\u200b.exe", name)
    assert meta["obfuscated_executable"] is True
    assert "U+200B" in label


def test_visible_name_with_embedded_zero_width_is_not_obfuscated() -> None:
    name = "Sp\u200botify.exe"
    label, meta = format_executable_label(r"C:\Apps\Spotify\Spotify.exe", name)
    assert label == name
    assert meta == {}


def test_format_executable_label_normal_exe_unchanged() -> None:
    label, meta = format_executable_label(
        r"C:\Apps\Cluely\Cluely.exe",
        "Cluely.exe",
    )
    assert label == "Cluely.exe"
    assert meta == {}


def test_format_process_identity_single_pid() -> None:
    event = DetectionEvent(
        id="x",
        severity="high",
        category="process",
        title="t",
        detail="d",
        process_name="Cluely.exe",
        pid=42,
        metadata={"display_name": "Cluely.exe"},
    )
    assert format_process_identity(event) == "process: Cluely.exe (pid=42)"


def test_format_process_identity_multi_pid_rollup() -> None:
    event = DetectionEvent(
        id="x",
        severity="cleared",
        category="product_session",
        title="t",
        detail="d",
        process_name="Weather Tracker.exe",
        metadata={
            "display_name": "Weather Tracker.exe",
            "pids_cleared": [18936, 15960],
        },
    )
    assert format_process_identity(event) == (
        "process: Weather Tracker.exe (pids=18936, 15960)"
    )


def test_format_process_identity_uses_main_pid_and_related_count() -> None:
    event = DetectionEvent(
        id="x",
        severity="high",
        category="process",
        title="t",
        detail="d",
        process_name="Weather Tracker.exe",
        pid=18940,
        metadata={
            "display_name": "Weather Tracker.exe",
            "anchor_pid": 4336,
            "instance_count": 4,
        },
    )
    assert format_process_identity(event) == (
        "process: Weather Tracker.exe (main pid 4336, 4 live processes)"
    )


def test_format_process_identity_overlay_shows_single_pid_only() -> None:
    event = DetectionEvent(
        id="x",
        severity="high",
        category="overlay",
        title="t",
        detail="d",
        process_name="Weather Tracker.exe",
        pid=4336,
        metadata={
            "display_name": "Weather Tracker.exe",
            "anchor_pid": 4336,
            "instance_count": 4,
        },
    )
    assert format_process_identity(event) == "process: Weather Tracker.exe (pid=4336)"


def test_format_process_identity_non_process_uses_event_pid_not_anchor() -> None:
    event = DetectionEvent(
        id="x",
        severity="high",
        category="overlay",
        title="t",
        detail="d",
        process_name="Weather Tracker.exe",
        pid=9001,
        metadata={
            "display_name": "Weather Tracker.exe",
            "anchor_pid": 4336,
            "instance_count": 4,
        },
    )
    assert format_process_identity(event) == "process: Weather Tracker.exe (pid=9001)"


def test_format_process_identity_lifecycle_process_uses_event_pid_only() -> None:
    event = DetectionEvent(
        id="x",
        severity="high",
        category="process",
        title="t",
        detail="d",
        process_name="Weather Tracker.exe",
        pid=18940,
        metadata={
            "display_name": "Weather Tracker.exe",
            "anchor_pid": 4336,
            "instance_count": 4,
            "lifecycle": "appeared",
        },
    )
    assert format_process_identity(event) == "process: Weather Tracker.exe (pid=18940)"


def test_format_process_identity_cleared_without_pids_omits_line() -> None:
    event = DetectionEvent(
        id="x",
        severity="cleared",
        category="product_session",
        title="t",
        detail="d",
        process_name="Weather Tracker.exe",
        metadata={"display_name": "Weather Tracker.exe"},
    )
    assert format_process_identity(event) is None


def test_format_pid_list_caps_overflow() -> None:
    from hortense.entity import format_pid_list

    line = format_pid_list([2448, 16972, 19028, 19072, 24296], cap=4)
    assert line == "pids: 2448, 16972, 19028, 19072 +1 more"


def test_pick_anchor_pid_prefers_tree_root() -> None:
    snapshot = [
        {"pid": 100, "parent_pid": 0, "exe": "root.exe", "path": r"C:\Apps\Tool\root.exe"},
        {"pid": 200, "parent_pid": 100, "exe": "worker.exe", "path": r"C:\Apps\Tool\worker.exe"},
    ]
    by_pid, _live = build_process_index(snapshot)
    anchor = pick_anchor_pid({100, 200}, by_pid)
    assert anchor == 100


def test_prefer_process_event_prefers_anchor_pid() -> None:
    current = DetectionEvent(
        id="process:worker",
        severity="high",
        category="process",
        title="t",
        detail="d",
        process_name="Tool.exe",
        pid=200,
        metadata={"anchor_pid": 100, "match_reason": "process name signature"},
    )
    candidate = DetectionEvent(
        id="process:root",
        severity="high",
        category="process",
        title="t",
        detail="d",
        process_name="Tool.exe",
        pid=100,
        metadata={"anchor_pid": 100, "match_reason": "process name signature"},
    )
    picked = prefer_process_event(current, candidate, 100)
    assert picked.pid == 100


def test_render_detail_line_substitutes_obfuscated_name() -> None:
    raw = "\u2800.exe"
    display = "parakeetai-desktop [U+2800].exe"
    event = DetectionEvent(
        id="x",
        severity="high",
        category="process",
        title="t",
        detail=f"Running process matched community signature: {raw}",
        process_name=raw,
        metadata={
            "display_name": display,
            "raw_process_name": raw,
            "obfuscated_executable": True,
        },
    )
    rendered = render_detail_line(event)
    assert raw not in rendered
    assert display in rendered
