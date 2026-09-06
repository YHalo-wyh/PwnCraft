import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUTOCORRECT = ROOT / "autocorrect"
PROJECT = ROOT / "pwncraft"
for path in (AUTOCORRECT, PROJECT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from challenge_intake import load_splits, split_for_case
from pwncraft.features.audit.extract import extract_exploit_ir

CASE_ID = "memory_write-asis-ctf-quals-2026-arena-snapshots-d4276d86"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth.json"


def test_asis2026_case_is_registered_train_before_feedback() -> None:
    splits = load_splits()
    assert split_for_case(CASE_ID, splits) == "train"


def test_truth_lock_points_to_recent_asis2026_material() -> None:
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    assert truth["domain"] == "memory_write"
    assert truth["event"]["name"] == "ASIS CTF Quals 2026"
    assert truth["source_class"] == "community_archive"
    assert truth["truth_lock"]["analyst_input_hashes"]["exploit_git_blob_sha1"] == \
        "d4276d8601f15f0f34b05ab42d9832c0a722e886"


def test_source_derived_socket_wrapper_semantics_are_visible() -> None:
    # Minimal source-derived fixture preserving the real challenge's wrapper
    # shape without treating the archive writeup as runtime observation.
    source = r'''
class Conn:
    def recv_line(self):
        data = self.s.recv(4096)
        return data

    def send_cmd(self, command):
        self.s.sendall((command + "\\n").encode())
        return self.recv_line()


def exploit(conn):
    conn.send_cmd("SNAP")


def main():
    exploit(Conn())
'''
    ir, error = extract_exploit_ir(source)
    assert error is None
    assert any(i.action == "SEND" and "SNAP" in i.value for i in ir.interactions)
    assert any(i.action == "RECV" and i.length == 4096 for i in ir.interactions)
