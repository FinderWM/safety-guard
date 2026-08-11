"""apply_patch parser tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


HOOKS_DIR = Path(__file__).resolve().parents[2]
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

from safety_guard.adapters.codex import parse_apply_patch  # noqa: E402


def test_parse_empty_patch_returns_empty_list():
    assert parse_apply_patch("") == []
    assert parse_apply_patch("   \n") == []


def test_parse_multiple_operations_and_quoted_paths():
    patch = """*** Begin Patch
*** Update File: "a dir/file one.txt"
@@
-old
+new
*** Add File: nested/path/new.txt
+hello
*** Delete File: old/legacy.py
*** End Patch
"""
    assert parse_apply_patch(patch) == [
        {"file_path": "a dir/file one.txt", "action": "update"},
        {"file_path": "nested/path/new.txt", "action": "add"},
        {"file_path": "old/legacy.py", "action": "delete"},
    ]


def test_parse_move_to_emits_delete_and_add():
    patch = """*** Begin Patch
*** Update File: old/name.txt
*** Move to: new/name.txt
@@
-old
+new
*** End Patch
"""
    assert parse_apply_patch(patch) == [
        {"file_path": "old/name.txt", "action": "delete"},
        {"file_path": "new/name.txt", "action": "add"},
    ]


@pytest.mark.parametrize(
    "patch",
    [
        "*** Update File: foo.txt\n@@\n-old\n+new\n*** End Patch\n",
        "*** Begin Patch\n*** Update File: foo.txt\n@@\n-old\n+new\n",
        "*** Begin Patch\n*** Move to: foo.txt\n*** End Patch\n",
        "*** Begin Patch\n*** Update File: foo.txt\n*** End Patch\ntrailing",
    ],
)
def test_parse_invalid_patch_raises(patch: str):
    with pytest.raises(ValueError):
        parse_apply_patch(patch)
