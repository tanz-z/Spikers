"""Tests for gateway/hash_chain.py  -  run:  python -m pytest tests/test_hash_chain.py -v"""
import json
import os
import sqlite3
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.hash_chain import HashChainLogger, normalize_category  # noqa: E402


@pytest.fixture
def lg(tmp_path):
    return HashChainLogger(str(tmp_path / "audit.db"), hmac_key="test-key")


def add(lg, n=1, **kw):
    for i in range(n):
        lg.log(request_id=f"req_{i}", user_id=kw.get("user", "user_general"),
               risk_input=kw.get("risk", 0.1), risk_output=0.0, risk_level="CLEAN",
               action="PASS", llm_route="PRIMARY", findings=kw.get("findings", []),
               category="CLEAN", policy="DEFAULT", latency_ms=100, llm_used="gemini")


def raw(lg, sql, params=()):
    c = sqlite3.connect(lg.db_path)
    c.execute(sql, params)
    c.commit()
    c.close()


def test_empty_chain_is_valid(lg):
    assert lg.verify_chain()["valid"] is True


def test_intact_chain_verifies(lg):
    add(lg, 10)
    r = lg.verify_chain()
    assert r["valid"] and r["entries"] == 10 and r["latest_hash"]


def test_editing_a_row_is_detected(lg):
    add(lg, 5)
    raw(lg, "UPDATE audit_chain SET action_taken='PASS', risk_score_input=0.0 WHERE seq=3")
    raw(lg, "UPDATE audit_chain SET user_id='someone_else' WHERE seq=3")
    r = lg.verify_chain()
    assert not r["valid"] and r["broken_at"] == 3 and r["failure_type"] == "HASH_MISMATCH"


def test_deleting_a_middle_row_is_detected(lg):
    add(lg, 5)
    raw(lg, "DELETE FROM audit_chain WHERE seq=3")
    r = lg.verify_chain()
    assert not r["valid"] and r["failure_type"] == "GAP"


def test_truncating_the_tail_is_detected(lg):
    """A plain hash chain cannot see this. The signed anchor can."""
    add(lg, 5)
    raw(lg, "DELETE FROM audit_chain WHERE seq IN (4,5)")
    r = lg.verify_chain()
    assert not r["valid"] and r["failure_type"] == "TRUNCATION"


def test_wiping_all_rows_is_detected(lg):
    add(lg, 3)
    raw(lg, "DELETE FROM audit_chain")
    assert not lg.verify_chain()["valid"]


def test_forging_anchor_without_key_is_detected(lg):
    add(lg, 5)
    raw(lg, "DELETE FROM audit_chain WHERE seq=5")
    raw(lg, "UPDATE chain_anchor SET head_seq=4, head_hash=(SELECT entry_hash FROM audit_chain WHERE seq=4)")
    r = lg.verify_chain()
    assert not r["valid"] and r["failure_type"] == "ANCHOR_FORGED"


def test_recomputing_hashes_without_key_fails(tmp_path):
    """Attacker edits a row and recomputes with plain SHA-256: still caught."""
    import hashlib
    lg = HashChainLogger(str(tmp_path / "a.db"), hmac_key="secret")
    add(lg, 3)
    raw(lg, "UPDATE audit_chain SET risk_score_input=0.0 WHERE seq=2")
    row = sqlite3.connect(lg.db_path).execute(
        "SELECT previous_hash FROM audit_chain WHERE seq=2").fetchone()[0]
    fake = hashlib.sha256(row.encode()).hexdigest()
    raw(lg, "UPDATE audit_chain SET entry_hash=? WHERE seq=2", (fake,))
    assert not lg.verify_chain()["valid"]


def test_wrong_key_cannot_verify(tmp_path):
    p = str(tmp_path / "k.db")
    add(HashChainLogger(p, hmac_key="key-A"), 3)
    assert not HashChainLogger(p, hmac_key="key-B").verify_chain()["valid"]
    assert HashChainLogger(p, hmac_key="key-A").verify_chain()["valid"]


def test_chain_survives_restart(tmp_path):
    p = str(tmp_path / "r.db")
    add(HashChainLogger(p, hmac_key="k"), 3)
    again = HashChainLogger(p, hmac_key="k")
    add(again, 2)
    r = again.verify_chain()
    assert r["valid"] and r["entries"] == 5


def test_concurrent_writes_never_fork_the_chain(lg):
    errors = []

    def worker():
        try:
            add(lg, 10)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    r = lg.verify_chain()
    assert r["valid"] and r["entries"] == 120
    seqs = [row["seq"] for row in lg.get_logs(limit=500)]
    assert sorted(seqs) == list(range(1, 121))


def test_two_logger_instances_share_one_chain(tmp_path):
    p = str(tmp_path / "m.db")
    a, b = HashChainLogger(p, hmac_key="k"), HashChainLogger(p, hmac_key="k")
    for _ in range(5):
        add(a)
        add(b)
    assert a.verify_chain()["valid"] and a.count() == 10


# ───────────────────────── privacy ─────────────────────────
def test_raw_sensitive_values_are_never_stored(lg):
    leaks = ["2345 6789 0123", "ABCPK1234F", "hunter2!", "Rajesh Kumar", "AKIAIOSFODNN7EXAMPLE"]
    findings = [{"type": "PII", "subtype": v} for v in leaks] + [{"type": "PII", "subtype": "AADHAAR"}]
    add(lg, findings=findings)
    dump = json.dumps(lg.get_logs(10))
    for v in leaks:
        assert v not in dump
    assert lg.get_logs(1)[0]["finding_types"] == ["AADHAAR", "OTHER"]
    assert lg.get_logs(1)[0]["finding_count"] == 6


def test_accepts_pydantic_style_objects(lg):
    class F:  # mimics gateway.models.Finding
        type, subtype = "PII", "PAN"
    add(lg, findings=[F()])
    assert lg.get_logs(1)[0]["finding_types"] == ["PAN"]


# ───────────────────── interface compatibility ─────────────────────
def test_pipeline_keyword_names_work(lg):
    h = lg.log(request_id="x", user_id="u", risk_input=0.9, risk_output=0.0,
               risk_level="CRITICAL", action="BLOCK", llm_route="BLOCKED",
               findings=[], category="PROMPT_INJECTION", policy="BLOCK",
               latency_ms=0, llm_used="BLOCKED")
    assert len(h) == 64


def test_legacy_keyword_names_still_work(lg):
    lg.log(request_id="x", user_id="u", risk_score_input=0.62, risk_score_output=0.0,
           risk_level="HIGH", action_taken="REDACT", llm_route="QUARANTINE",
           findings=[], category="PII", policy_triggered="PII_REDACT",
           latency_ms=5, llm_used="qwen3:4b")
    row = lg.get_logs(1)[0]
    assert row["action_taken"] == "REDACT" and row["risk_score_input"] == 0.62


@pytest.mark.parametrize("raw_cat,expected", [
    ("PII_LEAKAGE", "PII"), ("SECRET_EXPOSURE", "SECRET"), ("Prompt Injection", "PROMPT_INJECTION"),
    ("injection", "PROMPT_INJECTION"), ("Access Violation", "ACCESS_VIOLATION"),
    ("CLEAN", "CLEAN"), ("", "CLEAN"), (None, "CLEAN"),
])
def test_category_normalisation(raw_cat, expected):
    assert normalize_category(raw_cat) == expected


# ─────────────────────────── analytics ───────────────────────────
def test_stats_have_both_key_styles(lg):
    add(lg, 3)
    lg.log("b", "user_x", 0.95, 0.0, "CRITICAL", "BLOCK", "BLOCKED", [{"subtype": "JAILBREAK"}],
           "PROMPT_INJECTION", "BLOCK", 0, "none")
    s = lg.get_stats()
    assert s["total"] == s["total_requests"] == 4
    assert s["blocked"] == s["blocked_count"] == 1
    assert s["block_rate_pct"] == 25.0
    assert s["by_category"]["PROMPT_INJECTION"] == 1
    assert s["avg_latency_ms"] == 100.0  # zero-latency blocked rows excluded


def test_stats_on_empty_db(lg):
    assert lg.get_stats()["total"] == 0


def test_detection_breakdown_and_timeseries(lg):
    add(lg, 2, findings=[{"subtype": "AADHAAR"}, {"subtype": "PAN"}])
    add(lg, 1, findings=[{"subtype": "AADHAAR"}])
    assert lg.get_detection_breakdown() == {"AADHAAR": 3, "PAN": 2}
    ts = lg.get_timeseries(minutes=60, buckets=6)
    assert len(ts) == 6 and sum(b["total"] for b in ts) == 3