"""Run: python -m pytest tests/test_integrity.py -v"""
import os
import shutil
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.hash_chain import HashChainLogger  # noqa: E402
from gateway.integrity import check_integrity, get_head, inspect_rows  # noqa: E402


@pytest.fixture
def env(tmp_path):
    lg = HashChainLogger(str(tmp_path / "a.db"), hmac_key="k")
    for i in range(8):
        lg.log(f"r{i}", "u", 0.1, 0.0, "CLEAN", "BLOCK" if i % 2 else "PASS", "PRIMARY",
               [{"subtype": "PAN"}], "PII", "P", 5, "g")
    return lg, str(tmp_path / "receipt.json")


def raw(lg, sql):
    c = sqlite3.connect(lg.db_path)
    c.execute(sql)
    c.commit()
    c.close()


def test_clean_ledger_is_secure(env):
    lg, rc = env
    r = check_integrity(lg, rc)
    assert r["status"] == "SECURE" and r["alerts"] == [] and r["head_seq"] == 8
    assert all(x["status"] == "OK" for x in inspect_rows(lg))


def test_edited_row_is_pinpointed(env):
    lg, rc = env
    raw(lg, "UPDATE audit_chain SET action_taken='PASS' WHERE seq=4")
    r = check_integrity(lg, rc)
    assert r["status"] == "COMPROMISED" and r["tampered_seqs"] == [4]
    assert [x["seq"] for x in inspect_rows(lg) if x["status"] == "TAMPERED"] == [4]


def test_deleted_row_is_reported_as_gap(env):
    lg, rc = env
    raw(lg, "DELETE FROM audit_chain WHERE seq=5")
    r = check_integrity(lg, rc)
    assert r["status"] == "COMPROMISED" and r["alerts"][0]["type"] == "GAP"


def test_truncation_is_detected(env):
    lg, rc = env
    raw(lg, "DELETE FROM audit_chain WHERE seq > 6")
    types = {a["type"] for a in check_integrity(lg, rc)["alerts"]}
    assert "TRUNCATION" in types


def test_rollback_to_older_valid_copy_is_detected(env, tmp_path):
    lg, rc = env
    assert check_integrity(lg, rc)["status"] == "SECURE"       # witnesses head #8
    old = str(tmp_path / "old.db")
    shutil.copy(lg.db_path, old)
    lg.log("new", "u", 0.1, 0.0, "CLEAN", "PASS", "PRIMARY", [], "CLEAN", "P", 5, "g")
    assert check_integrity(lg, rc)["status"] == "SECURE"       # witnesses head #9
    shutil.copy(old, lg.db_path)                               # attacker swaps in the old copy
    r = check_integrity(lg, rc)
    assert r["status"] == "COMPROMISED" and any(a["type"] == "ROLLBACK" for a in r["alerts"])


def test_compromised_state_is_not_witnessed(env):
    lg, rc = env
    check_integrity(lg, rc)
    raw(lg, "UPDATE audit_chain SET risk_score_input=0 WHERE seq=2")
    check_integrity(lg, rc)
    assert check_integrity(lg, rc)["status"] == "COMPROMISED"  # stays red, never "forgets"


def test_forged_receipt_is_detected(env):
    lg, rc = env
    check_integrity(lg, rc)
    with open(rc, "w") as f:
        f.write('{"seq": 3, "hash": "x", "mac": "bad"}')
    assert any(a["type"] == "RECEIPT_FORGED" for a in check_integrity(lg, rc)["alerts"])


def test_get_head_on_empty_ledger(tmp_path):
    assert get_head(HashChainLogger(str(tmp_path / "e.db"), hmac_key="k"))["seq"] == 0
