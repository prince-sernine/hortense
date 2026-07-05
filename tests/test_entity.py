from __future__ import annotations

from hortense.entity import build_process_index, product_key


def test_product_key_shared_across_parent_and_child() -> None:
    snapshot = [
        {"pid": 100, "parent_pid": 0, "exe": "InterviewMan.exe", "path": r"C:\Apps\InterviewMan\InterviewMan.exe"},
        {"pid": 200, "parent_pid": 100, "exe": "helper.exe", "path": r"C:\Apps\InterviewMan\helper.exe"},
    ]
    by_pid, live = build_process_index(snapshot)
    parent_key = product_key(100, r"C:\Apps\InterviewMan\InterviewMan.exe", by_pid=by_pid, live_pids=live)
    child_key = product_key(200, r"C:\Apps\InterviewMan\helper.exe", by_pid=by_pid, live_pids=live)
    assert parent_key == child_key
