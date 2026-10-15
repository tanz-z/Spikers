"""
gateway/hash_chain.py - Tamper-Proof Cryptographic Audit Logger
Owner: Bhoomi

Features:
- SHA-256 hash chaining (blockchain-like integrity)
- SQLite persistent storage
- Privacy-aware: NEVER stores actual sensitive prompt values, only entity TYPES and COUNTS
- Tamper detection method (re-computes chain hashes to verify DB integrity)
- Analytics helper for Streamlit dashboard KPIs
"""

import os
import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Path where audit database will be stored
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "audit_log.db")
GENESIS_HASH = "0" * 64  # Initial hash for the first record in chain


class HashChainLogger:
    """Tamper-evident audit logger using SHA-256 hash chaining."""

    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize audit chain SQLite table."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    risk_score_input REAL NOT NULL,
                    risk_score_output REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    llm_route TEXT NOT NULL,
                    finding_types TEXT NOT NULL,
                    finding_count INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    policy_triggered TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    llm_used TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                )
            """)
            conn.commit()

    def _compute_hash(self, payload: Dict[str, Any], previous_hash: str) -> str:
        """Compute deterministic SHA-256 hash of entry data + previous entry hash."""
        # Include previous hash in canonical representation
        data_to_hash = {
            "payload": payload,
            "previous_hash": previous_hash
        }
        canonical_json = json.dumps(data_to_hash, sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def _get_latest_hash(self) -> str:
        """Fetch the entry_hash of the most recent log record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else GENESIS_HASH

    def log(
        self,
        request_id: str,
        user_id: str,
        risk_score_input: float,
        risk_score_output: float,
        risk_level: str,
        action_taken: str,
        llm_route: str,
        findings: List[Dict[str, Any]],
        category: str,
        policy_triggered: str,
        latency_ms: float,
        llm_used: str
    ) -> str:
        """
        Log a new gateway transaction to the tamper-proof chain.
        
        PRIVACY RULE: We ONLY extract threat types (e.g. 'AADHAAR', 'PAN'),
        NEVER the actual sensitive content or raw text!
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Extract only threat types and count (NO RAW VALUES STORED)
        finding_types = list(set([f.get("subtype", f.get("type", "UNKNOWN")) for f in findings]))
        finding_count = len(findings)

        previous_hash = self._get_latest_hash()

        # Core payload used for cryptographic hashing
        payload = {
            "timestamp": timestamp,
            "request_id": request_id,
            "user_id": user_id,
            "risk_score_input": round(risk_score_input, 4),
            "risk_score_output": round(risk_score_output, 4),
            "risk_level": risk_level,
            "action_taken": action_taken,
            "llm_route": llm_route,
            "finding_types": finding_types,
            "finding_count": finding_count,
            "category": category,
            "policy_triggered": policy_triggered,
            "latency_ms": round(latency_ms, 2),
            "llm_used": llm_used
        }

        entry_hash = self._compute_hash(payload, previous_hash)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_chain (
                    timestamp, request_id, user_id, risk_score_input, risk_score_output,
                    risk_level, action_taken, llm_route, finding_types, finding_count,
                    category, policy_triggered, latency_ms, llm_used, previous_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, request_id, user_id,
                payload["risk_score_input"], payload["risk_score_output"],
                risk_level, action_taken, llm_route,
                json.dumps(finding_types), finding_count,
                category, policy_triggered, payload["latency_ms"], llm_used,
                previous_hash, entry_hash
            ))
            conn.commit()

        return entry_hash

    def verify_chain(self) -> Dict[str, Any]:
        """
        Walk the entire database chain and verify SHA-256 integrity.
        Detects if any row was edited, inserted, or deleted!
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, request_id, user_id, risk_score_input, risk_score_output,
                       risk_level, action_taken, llm_route, finding_types, finding_count,
                       category, policy_triggered, latency_ms, llm_used, previous_hash, entry_hash
                FROM audit_chain ORDER BY id ASC
            """)
            rows = cursor.fetchall()

        if not rows:
            return {"valid": True, "total_records": 0, "message": "Audit log is empty."}

        expected_previous_hash = GENESIS_HASH

        for idx, row in enumerate(rows):
            (
                row_id, timestamp, request_id, user_id, risk_in, risk_out,
                risk_lvl, action, route, finding_types_json, finding_cnt,
                cat, policy, latency, llm, prev_hash, stored_entry_hash
            ) = row

            # 1. Verify link to previous entry
            if prev_hash != expected_previous_hash:
                return {
                    "valid": False,
                    "broken_at_id": row_id,
                    "index": idx,
                    "reason": f"Broken chain link at record #{row_id}. Expected previous hash {expected_previous_hash[:12]}..., got {prev_hash[:12]}...",
                    "message": f"🚨 TAMPERING DETECTED at record #{row_id}!"
                }

            # 2. Re-compute current hash from database values
            payload = {
                "timestamp": timestamp,
                "request_id": request_id,
                "user_id": user_id,
                "risk_score_input": round(risk_in, 4),
                "risk_score_output": round(risk_out, 4),
                "risk_level": risk_lvl,
                "action_taken": action,
                "llm_route": route,
                "finding_types": json.loads(finding_types_json),
                "finding_count": finding_cnt,
                "category": cat,
                "policy_triggered": policy,
                "latency_ms": round(latency, 2),
                "llm_used": llm
            }
            recalculated_hash = self._compute_hash(payload, prev_hash)

            # 3. Check hash equality
            if recalculated_hash != stored_entry_hash:
                return {
                    "valid": False,
                    "broken_at_id": row_id,
                    "index": idx,
                    "reason": f"Hash mismatch at record #{row_id}. Data inside this row was modified after creation!",
                    "message": f"🚨 TAMPERING DETECTED: Data altered in record #{row_id}!"
                }

            expected_previous_hash = stored_entry_hash

        return {
            "valid": True,
            "total_records": len(rows),
            "latest_hash": expected_previous_hash[:16] + "...",
            "message": "🔒 Audit log chain integrity verified! Zero tampering detected."
        }

    def get_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent logs for Streamlit dashboard table."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, request_id, user_id, risk_score_input, risk_score_output,
                       risk_level, action_taken, llm_route, finding_types, finding_count,
                       category, policy_triggered, latency_ms, llm_used, previous_hash, entry_hash
                FROM audit_chain ORDER BY id DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()

        logs = []
        for r in rows:
            logs.append({
                "id": r[0],
                "timestamp": r[1],
                "request_id": r[2],
                "user_id": r[3],
                "risk_score_input": r[4],
                "risk_score_output": r[5],
                "risk_level": r[6],
                "action_taken": r[7],
                "llm_route": r[8],
                "finding_types": json.loads(r[9]),
                "finding_count": r[10],
                "category": r[11],
                "policy_triggered": r[12],
                "latency_ms": r[13],
                "llm_used": r[14],
                "previous_hash": r[15],
                "entry_hash": r[16]
            })
        return logs

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics for Streamlit Dashboard Tab 1 KPIs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM audit_chain")
            total_requests = cursor.fetchone()[0]

            if total_requests == 0:
                return {
                    "total_requests": 0, "blocked_count": 0, "quarantined_count": 0,
                    "block_rate_pct": 0.0, "avg_latency_ms": 0.0, "avg_risk_input": 0.0,
                    "avg_risk_output": 0.0, "by_action": {}, "by_risk_level": {},
                    "by_category": {}, "by_llm_route": {}
                }

            cursor.execute("SELECT COUNT(*) FROM audit_chain WHERE action_taken = 'BLOCK'")
            blocked_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_chain WHERE llm_route = 'QUARANTINE'")
            quarantined_count = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(latency_ms), AVG(risk_score_input), AVG(risk_score_output) FROM audit_chain")
            avg_lat, avg_in, avg_out = cursor.fetchone()

            # Helper for frequency distributions
            def get_counts(column):
                cursor.execute(f"SELECT {column}, COUNT(*) FROM audit_chain GROUP BY {column}")
                return dict(cursor.fetchall())

            return {
                "total_requests": total_requests,
                "blocked_count": blocked_count,
                "quarantined_count": quarantined_count,
                "block_rate_pct": round((blocked_count / total_requests) * 100, 1),
                "avg_latency_ms": round(avg_lat or 0, 1),
                "avg_risk_input": round(avg_in or 0, 2),
                "avg_risk_output": round(avg_out or 0, 2),
                "by_action": get_counts("action_taken"),
                "by_risk_level": get_counts("risk_level"),
                "by_category": get_counts("category"),
                "by_llm_route": get_counts("llm_route")
            }


# ─── QUICK TEST / VERIFICATION ───
if __name__ == "__main__":
    logger = HashChainLogger()

    print("--- 1. Logging Sample Requests ---")
    h1 = logger.log(
        request_id="req_001", user_id="user_general", risk_score_input=0.1,
        risk_score_output=0.0, risk_level="CLEAN", action_taken="PASS",
        llm_route="PRIMARY", findings=[], category="CLEAN",
        policy_triggered="DEFAULT_PASS", latency_ms=120.5, llm_used="gemini-1.5-flash"
    )
    print(f"Entry 1 Hash: {h1[:16]}...")

    h2 = logger.log(
        request_id="req_002", user_id="user_hr", risk_score_input=0.75,
        risk_score_output=0.0, risk_level="HIGH", action_taken="REDACT",
        llm_route="QUARANTINE", findings=[{"type": "PII", "subtype": "AADHAAR"}, {"type": "PII", "subtype": "PAN"}],
        category="PII", policy_triggered="PII_REDACT_POLICY", latency_ms=310.2, llm_used="qwen3:4b"
    )
    print(f"Entry 2 Hash: {h2[:16]}...")

    print("\n--- 2. Verifying Hash Chain Integrity ---")
    verification = logger.verify_chain()
    print(f"Chain Status: {verification['message']}")
    print(f"Total Logged: {verification['total_records']}")

    print("\n--- 3. Dashboard Analytics Stats ---")
    stats = logger.get_stats()
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Action Counts:  {stats['by_action']}")
    print(f"Risk Levels:    {stats['by_risk_level']}")