"""
gateway/integrity.py - Tamper forensics + live integrity monitor for the audit ledger
Owner: Bhoomi

hash_chain.py answers "is the chain valid?" with the FIRST break it finds.
This module answers the questions the IT admin actually asks:

  * WHICH rows were edited / deleted?           -> inspect_rows()
  * Is the whole ledger trustworthy right now?  -> check_integrity()
  * Was the DB swapped for an OLDER (valid) copy? -> signed head receipt (rollback check)

It only READS the ledger (never writes to audit_chain), so it can be polled
by the admin dashboard every few seconds without any risk.
"""

from __future__ import annotations

import hmac
import json
import os
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gateway.hash_chain import GENESIS_HASH, HashChainLogger

RECEIPT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "head_receipt.json"
)

_SELECT_ALL = """
    SELECT seq, timestamp, request_id, user_id, risk_score_input, risk_score_output,
           risk_level, action_taken, llm_route, finding_types, finding_count, category,
           policy_triggered, latency_ms, llm_used, previous_hash, entry_hash
    FROM audit_chain ORDER BY seq ASC
"""

# Highest-priority problem wins when a row has several.
_PRIORITY = ("TAMPERED", "GAP", "BROKEN_LINK")


# ───────────────────────────── per-row forensics ─────────────────────────────
def inspect_rows(logger: HashChainLogger, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Verify EVERY row independently. Newest first.

    status:
      OK           row hash re-derives correctly and links to its predecessor
      TAMPERED     row contents were modified after being written
      GAP          rows are missing immediately before this one (deleted / inserted)
      BROKEN_LINK  previous_hash does not match the predecessor's hash
    """
    with closing(logger._connect()) as conn:
        rows = conn.execute(_SELECT_ALL).fetchall()

    out: List[Dict[str, Any]] = []
    expected_prev, expected_seq = GENESIS_HASH, 1

    for r in rows:
        (seq, ts, req, uid, r_in, r_out, level, action, route, ftypes, fcount,
         cat, policy, latency, llm, prev_hash, stored_hash) = r

        issues: List[str] = []
        if seq != expected_seq:
            issues.append("GAP")
        if prev_hash != expected_prev:
            issues.append("BROKEN_LINK")

        try:
            labels = json.loads(ftypes)
            payload = logger._payload(seq, ts, req, uid, r_in, r_out, level, action, route,
                                      labels, fcount, cat, policy, latency, llm)
            if not hmac.compare_digest(logger._entry_hash(payload, prev_hash), stored_hash):
                issues.append("TAMPERED")
        except Exception:
            labels = []
            issues.append("TAMPERED")

        status = next((p for p in _PRIORITY if p in issues), "OK")
        out.append({
            "seq": seq, "timestamp": ts, "user_id": uid, "category": cat,
            "action_taken": action, "risk_level": level, "risk_score_input": r_in,
            "finding_types": labels, "entry_hash": stored_hash, "previous_hash": prev_hash,
            "status": status, "issues": issues,
        })
        expected_prev, expected_seq = stored_hash, seq + 1

    out.reverse()  # newest first, like get_logs()
    return out[:limit] if limit else out


def get_head(logger: HashChainLogger) -> Dict[str, Any]:
    """Latest entry's seq + hash (what you'd show as 'chain head' in the UI)."""
    with closing(logger._connect()) as conn:
        row = conn.execute(
            "SELECT seq, entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    return {"seq": row[0], "hash": row[1]} if row else {"seq": 0, "hash": GENESIS_HASH}


# ───────────────────────── signed head receipt (rollback check) ─────────────────────────
def _receipt_mac(logger: HashChainLogger, seq: int, head_hash: str) -> str:
    return logger._mac(f"RECEIPT|{seq}|{head_hash}")


def _load_receipt(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        return None


def _save_receipt(logger: HashChainLogger, path: str, seq: int, head_hash: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "seq": seq, "hash": head_hash,
            "mac": _receipt_mac(logger, seq, head_hash),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }, f)


# ───────────────────────────── one-call health check ─────────────────────────────
def check_integrity(logger: HashChainLogger, receipt_path: str = RECEIPT_PATH) -> Dict[str, Any]:
    """Full integrity report - safe to call on every dashboard refresh.

    Returns {status: SECURE|COMPROMISED, alerts: [...], tampered_seqs: [...], ...}
    """
    verify = logger.verify_chain()
    rows_newest_first = inspect_rows(logger)
    head = get_head(logger)

    alerts: List[Dict[str, Any]] = []
    bad = [r for r in rows_newest_first if r["status"] != "OK"]
    tampered_seqs = sorted(r["seq"] for r in bad)

    for r in sorted(bad, key=lambda x: x["seq"]):
        alerts.append({"type": r["status"], "seq": r["seq"],
                       "detail": f"Record #{r['seq']}: {', '.join(r['issues'])}"})

    # Tail truncation / forged anchor are invisible to per-row checks; verify_chain sees them.
    if not verify["valid"] and verify.get("failure_type") in (
            "TRUNCATION", "ANCHOR_FORGED", "ANCHOR_MISSING"):
        alerts.append({"type": verify["failure_type"], "seq": verify.get("broken_at"),
                       "detail": verify["reason"]})

    # Rollback: someone restored an older (internally valid) copy of the database.
    receipt = _load_receipt(receipt_path)
    if receipt:
        if not hmac.compare_digest(
                _receipt_mac(logger, int(receipt.get("seq", -1)), str(receipt.get("hash", ""))),
                str(receipt.get("mac", ""))):
            alerts.append({"type": "RECEIPT_FORGED", "seq": None,
                           "detail": "Head receipt signature is invalid"})
        else:
            r_seq, r_hash = int(receipt["seq"]), receipt["hash"]
            if head["seq"] < r_seq:
                alerts.append({"type": "ROLLBACK", "seq": head["seq"],
                               "detail": f"Ledger ends at #{head['seq']} but #{r_seq} was previously "
                                         f"witnessed - newer entries were removed or an old copy restored"})
            else:
                at = next((r for r in rows_newest_first if r["seq"] == r_seq), None)
                if at is None or at["entry_hash"] != r_hash:
                    alerts.append({"type": "HISTORY_REWRITTEN", "seq": r_seq,
                                   "detail": f"Entry #{r_seq} no longer matches the hash witnessed earlier"})

    status = "SECURE" if not alerts else "COMPROMISED"
    if status == "SECURE" and head["seq"] > 0:
        _save_receipt(logger, receipt_path, head["seq"], head["hash"])  # advance the witness

    return {
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "entries": verify.get("entries", len(rows_newest_first)),
        "head_seq": head["seq"],
        "head_hash": head["hash"],
        "alerts": alerts,
        "tampered_seqs": tampered_seqs,
        "verify": verify,
    }
