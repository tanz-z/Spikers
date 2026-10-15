"""
gateway/hash_chain.py - Tamper-evident, privacy-by-construction audit ledger
Owner: Bhoomi

What this module guarantees
---------------------------
1. TAMPER-EVIDENT   Every entry is HMAC-SHA256(key, entry + previous_entry_hash).
                    Editing, deleting, inserting or re-ordering ANY row breaks
                    the chain and verify_chain() reports the exact sequence no.
2. TRUNCATION-SAFE  A signed "head anchor" (seq + hash) is updated in the same
                    transaction as every append. Chopping rows off the END of
                    the log (which a plain hash chain cannot see) is detected.
3. FORGERY-RESISTANT Because the chain is keyed (HMAC), someone with only
                    file access to the .db cannot simply recompute every hash
                    after editing a row. Set AUDIT_HMAC_KEY in .env.
4. RACE-FREE        Appends are serialised (process lock + SQLite
                    BEGIN IMMEDIATE), so concurrent FastAPI requests can never
                    fork the chain.
5. PRIVACY-BY-CONSTRUCTION  Only short UPPER_SNAKE labels (e.g. "AADHAAR") are
                    ever persisted for findings. Even a buggy caller passing a
                    raw value cannot get it into the ledger - it is dropped.

Interface contract (Tanya's pipeline.py calls this):
    log(request_id, user_id, risk_input, risk_output, risk_level, action,
        llm_route, findings, category, policy, latency_ms, llm_used) -> str
The older keyword names (risk_score_input, action_taken, policy_triggered)
are still accepted as aliases, so nothing already written breaks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import warnings
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

try:  # optional: pick up AUDIT_HMAC_KEY from .env if python-dotenv is present
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "audit_log.db")
GENESIS_HASH = "0" * 64

# Used only when AUDIT_HMAC_KEY is not set, so the demo works out of the box.
_DEV_KEY = "spikers-dev-key-CHANGE-ME"

# Canonical vocabulary for the `category` column. Anything a teammate sends is
# normalised into this set so dashboard charts never fragment into
# "PII" / "PII_LEAKAGE" / "Pii" etc.
CATEGORIES = ("CLEAN", "PII", "SECRET", "PROMPT_INJECTION", "ACCESS_VIOLATION")
_CATEGORY_ALIASES = {
    "CLEAN": "CLEAN",
    "PII": "PII",
    "PII_LEAKAGE": "PII",
    "SECRET": "SECRET",
    "SECRETS": "SECRET",
    "SECRET_EXPOSURE": "SECRET",
    "INJECTION": "PROMPT_INJECTION",
    "PROMPT_INJECTION": "PROMPT_INJECTION",
    "ACCESS": "ACCESS_VIOLATION",
    "ACCESS_VIOLATION": "ACCESS_VIOLATION",
}

_LABEL_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,39}$")

# Privacy allow-list. ONLY these entity-type names can ever be written to the
# ledger; anything else is stored as "OTHER". (A shape check alone is not
# enough: a PAN like ABCPK1234F or an AWS key is also "uppercase letters and
# digits".) Add new detector types with register_labels().
ALLOWED_LABELS = {
    # PII / secrets (Lakshita's inspector + Presidio)
    "AADHAAR", "PAN", "INDIAN_PHONE", "PHONE", "PHONE_NUMBER", "EMAIL", "EMAIL_ADDRESS",
    "CREDIT_CARD", "PERSON", "PERSON_NAME", "IP_ADDRESS", "SSN", "US_SSN", "LOCATION",
    "UPI_ID", "PASSWORD", "PRIVATE_KEY", "JWT", "JWT_TOKEN", "AWS_KEY", "AWS_ACCESS",
    "AWS_SECRET", "API_KEY", "GENERIC_API_KEY", "GENERIC_SECRET", "GITHUB_TOKEN",
    "GOOGLE_API_KEY", "OPENAI_KEY", "SECRET",
    # injection
    "INSTRUCTION_OVERRIDE", "SYSTEM_PROMPT_EXTRACT", "ROLE_HIJACK", "JAILBREAK",
    "DATA_EXTRACTION", "CONTEXT_MANIPULATION", "ENCODING_ATTACK", "SOCIAL_ENGINEERING",
    "ML_DETECTED", "ML_CLASSIFIER", "INJECTION", "PII",
    # access control / output
    "ACCESS_VIOLATION", "UNAUTHORIZED_DOC", "OUTPUT_LEAK",
}


def register_labels(*labels: str) -> None:
    """Allow additional detector entity types to appear in the ledger."""
    for lbl in labels:
        if _LABEL_RE.match(str(lbl)):
            ALLOWED_LABELS.add(str(lbl))


def normalize_category(raw: Any) -> str:
    key = re.sub(r"[\s\-]+", "_", str(raw or "CLEAN").strip()).upper()
    return _CATEGORY_ALIASES.get(key, "CLEAN" if not key else key if _LABEL_RE.match(key) else "UNKNOWN")


def _safe_label(value: Any) -> str:
    """Map a finding's type to an allow-listed label, else "OTHER".

    This is the privacy firewall: '2345 6789 0123', 'ABCPK1234F' or 'hunter2!'
    are not in ALLOWED_LABELS, so the raw value is never persisted.
    """
    if not isinstance(value, str):
        return "OTHER"
    candidate = value.strip()
    return candidate if candidate in ALLOWED_LABELS else "OTHER"


def _finding_label(f: Any) -> str:
    """Extract a type label from a dict or a pydantic Finding."""
    if isinstance(f, dict):
        raw = f.get("subtype") or f.get("type")
    else:
        raw = getattr(f, "subtype", None) or getattr(f, "type", None)
    return _safe_label(raw)


class HashChainLogger:
    """Append-only, keyed hash-chained audit log backed by SQLite."""

    def __init__(self, db_path: str = DB_PATH, hmac_key: Optional[str] = None):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.db_path = db_path
        key = hmac_key or os.getenv("AUDIT_HMAC_KEY")
        self.using_default_key = not key
        if self.using_default_key:
            warnings.warn(
                "AUDIT_HMAC_KEY not set - using the built-in development key. "
                "Set it in .env for a forgery-resistant ledger.",
                stacklevel=2,
            )
            key = _DEV_KEY
        self._key = key.encode("utf-8")
        self._lock = threading.Lock()
        self._init_db()

    # ───────────────────────── connection / schema ─────────────────────────
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seq INTEGER NOT NULL UNIQUE,
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
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_anchor (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    head_seq INTEGER NOT NULL,
                    head_hash TEXT NOT NULL,
                    mac TEXT NOT NULL
                )
                """
            )

    # ───────────────────────────── crypto helpers ──────────────────────────
    def _mac(self, message: str) -> str:
        return hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def _entry_hash(self, payload: Dict[str, Any], previous_hash: str) -> str:
        canonical = json.dumps(
            {"payload": payload, "previous_hash": previous_hash},
            sort_keys=True,
            separators=(",", ":"),
        )
        return self._mac(canonical)

    def _anchor_mac(self, seq: int, head_hash: str) -> str:
        return self._mac(f"ANCHOR|{seq}|{head_hash}")

    @staticmethod
    def _payload(seq, ts, request_id, user_id, r_in, r_out, level, action, route,
                 finding_types, finding_count, category, policy, latency, llm) -> Dict[str, Any]:
        return {
            "seq": seq,
            "timestamp": ts,
            "request_id": request_id,
            "user_id": user_id,
            "risk_score_input": round(float(r_in), 4),
            "risk_score_output": round(float(r_out), 4),
            "risk_level": level,
            "action_taken": action,
            "llm_route": route,
            "finding_types": list(finding_types),
            "finding_count": int(finding_count),
            "category": category,
            "policy_triggered": policy,
            "latency_ms": round(float(latency), 2),
            "llm_used": llm,
        }

    # ─────────────────────────────── append ────────────────────────────────
    def log(
        self,
        request_id: str,
        user_id: str,
        risk_input: Optional[float] = None,
        risk_output: Optional[float] = None,
        risk_level: str = "CLEAN",
        action: Optional[str] = None,
        llm_route: str = "PRIMARY",
        findings: Optional[Iterable[Any]] = None,
        category: str = "CLEAN",
        policy: Optional[str] = None,
        latency_ms: float = 0.0,
        llm_used: str = "none",
        *,
        # backwards-compatible aliases (older code in this repo used these)
        risk_score_input: Optional[float] = None,
        risk_score_output: Optional[float] = None,
        action_taken: Optional[str] = None,
        policy_triggered: Optional[str] = None,
        timestamp: Optional[str] = None,  # demo seeding only; the API never sets this
    ) -> str:
        """Append one transaction to the chain and return its entry hash."""
        r_in = risk_input if risk_input is not None else (risk_score_input or 0.0)
        r_out = risk_output if risk_output is not None else (risk_score_output or 0.0)
        act = str(action or action_taken or "PASS").upper()
        pol = str(policy or policy_triggered or f"{act}_POLICY")

        findings = list(findings or [])
        labels = sorted({_finding_label(f) for f in findings})
        count = len(findings)
        cat = normalize_category(category)
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")  # cross-process write lock
            try:
                row = conn.execute(
                    "SELECT seq, entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_seq, prev_hash = (row[0], row[1]) if row else (0, GENESIS_HASH)
                seq = prev_seq + 1

                payload = self._payload(
                    seq, ts, str(request_id), str(user_id), r_in, r_out,
                    str(risk_level).upper(), act, str(llm_route).upper(),
                    labels, count, cat, pol, latency_ms, str(llm_used),
                )
                entry_hash = self._entry_hash(payload, prev_hash)

                conn.execute(
                    """
                    INSERT INTO audit_chain (
                        seq, timestamp, request_id, user_id, risk_score_input,
                        risk_score_output, risk_level, action_taken, llm_route,
                        finding_types, finding_count, category, policy_triggered,
                        latency_ms, llm_used, previous_hash, entry_hash
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        seq, ts, payload["request_id"], payload["user_id"],
                        payload["risk_score_input"], payload["risk_score_output"],
                        payload["risk_level"], act, payload["llm_route"],
                        json.dumps(labels), count, cat, pol,
                        payload["latency_ms"], payload["llm_used"], prev_hash, entry_hash,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO chain_anchor (id, head_seq, head_hash, mac)
                    VALUES (1, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        head_seq=excluded.head_seq,
                        head_hash=excluded.head_hash,
                        mac=excluded.mac
                    """,
                    (seq, entry_hash, self._anchor_mac(seq, entry_hash)),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return entry_hash

    # ─────────────────────────────── verify ────────────────────────────────
    def verify_chain(self) -> Dict[str, Any]:
        """Re-derive the whole chain and check links, hashes and the anchor."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT seq, timestamp, request_id, user_id, risk_score_input,
                       risk_score_output, risk_level, action_taken, llm_route,
                       finding_types, finding_count, category, policy_triggered,
                       latency_ms, llm_used, previous_hash, entry_hash
                FROM audit_chain ORDER BY seq ASC
                """
            ).fetchall()
            anchor = conn.execute(
                "SELECT head_seq, head_hash, mac FROM chain_anchor WHERE id = 1"
            ).fetchone()

        def fail(seq, kind, reason, idx):
            return {
                "valid": False, "entries": len(rows), "total_records": len(rows),
                "broken_at": seq, "broken_at_id": seq, "index": idx,
                "failure_type": kind, "reason": reason,
                "message": f"TAMPERING DETECTED at record #{seq}: {reason}",
            }

        if not rows:
            if anchor and anchor[0] > 0:
                return fail(0, "TRUNCATION",
                            f"ledger is empty but anchor says {anchor[0]} entries existed", 0)
            return {"valid": True, "entries": 0, "total_records": 0, "broken_at": None,
                    "latest_hash": None, "message": "Audit log is empty."}

        expected_prev, expected_seq = GENESIS_HASH, 1
        for idx, r in enumerate(rows):
            (seq, ts, req, uid, r_in, r_out, level, action, route, ftypes, fcount,
             cat, policy, latency, llm, prev_hash, stored_hash) = r

            if seq != expected_seq:
                return fail(expected_seq, "GAP",
                            f"sequence jumps from {expected_seq - 1} to {seq} - row(s) deleted or inserted", idx)
            if prev_hash != expected_prev:
                return fail(seq, "BROKEN_LINK",
                            f"link to previous entry does not match ({prev_hash[:10]}... vs {expected_prev[:10]}...)", idx)
            try:
                labels = json.loads(ftypes)
            except Exception:
                return fail(seq, "CORRUPT", "finding_types is not valid JSON", idx)

            payload = self._payload(seq, ts, req, uid, r_in, r_out, level, action, route,
                                    labels, fcount, cat, policy, latency, llm)
            if not hmac.compare_digest(self._entry_hash(payload, prev_hash), stored_hash):
                hint = ""
                if seq == 1 and self.using_default_key:
                    hint = " (if AUDIT_HMAC_KEY changed since this log was created, delete data/audit_log.db)"
                return fail(seq, "HASH_MISMATCH", "row contents were modified after being written" + hint, idx)

            expected_prev, expected_seq = stored_hash, seq + 1

        last_seq, last_hash = rows[-1][0], rows[-1][16]
        if anchor is None:
            return fail(last_seq, "ANCHOR_MISSING", "head anchor is missing - cannot prove the log was not truncated", len(rows) - 1)
        a_seq, a_hash, a_mac = anchor
        if not hmac.compare_digest(self._anchor_mac(a_seq, a_hash), a_mac):
            return fail(last_seq, "ANCHOR_FORGED", "head anchor signature is invalid", len(rows) - 1)
        if (a_seq, a_hash) != (last_seq, last_hash):
            return fail(a_seq, "TRUNCATION",
                        f"anchor records {a_seq} entries but ledger ends at {last_seq} - tail was removed", len(rows) - 1)

        return {
            "valid": True, "entries": len(rows), "total_records": len(rows),
            "broken_at": None, "latest_hash": last_hash,
            "message": f"Chain intact: {len(rows)} entries verified (links, signatures, head anchor).",
        }

    # ─────────────────────────────── queries ───────────────────────────────
    _COLS = ("seq", "timestamp", "request_id", "user_id", "risk_score_input",
             "risk_score_output", "risk_level", "action_taken", "llm_route",
             "finding_types", "finding_count", "category", "policy_triggered",
             "latency_ms", "llm_used", "previous_hash", "entry_hash")

    def get_logs(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Newest-first. `id` is kept as an alias of `seq` for older callers."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT {', '.join(self._COLS)} FROM audit_chain "
                "ORDER BY seq DESC LIMIT ? OFFSET ?",
                (int(limit), int(offset)),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(zip(self._COLS, r))
            try:
                d["finding_types"] = json.loads(d["finding_types"])
            except Exception:
                d["finding_types"] = []
            d["id"] = d["seq"]
            out.append(d)
        return out

    def get_stats(self) -> Dict[str, Any]:
        """Aggregates for the dashboard. Both `total` and `total_requests` exist."""
        with closing(self._connect()) as conn:
            total = conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]

            def grouped(col: str) -> Dict[str, int]:
                return dict(conn.execute(
                    f"SELECT {col}, COUNT(*) FROM audit_chain GROUP BY {col}").fetchall())

            if total == 0:
                return {
                    "total": 0, "total_requests": 0, "blocked": 0, "blocked_count": 0,
                    "quarantined": 0, "quarantined_count": 0, "redacted": 0,
                    "flagged_count": 0, "unique_users": 0, "block_rate_pct": 0.0,
                    "avg_latency_ms": 0.0, "avg_risk_input": 0.0, "avg_risk_output": 0.0,
                    "by_action": {}, "by_risk_level": {}, "by_category": {},
                    "by_llm_route": {}, "by_user": {},
                }
            by_action = grouped("action_taken")
            by_route = grouped("llm_route")
            blocked = by_action.get("BLOCK", 0)
            avg_lat = conn.execute(
                "SELECT AVG(latency_ms) FROM audit_chain WHERE latency_ms > 0").fetchone()[0]
            avg_in, avg_out = conn.execute(
                "SELECT AVG(risk_score_input), AVG(risk_score_output) FROM audit_chain").fetchone()
            return {
                "total": total, "total_requests": total,
                "blocked": blocked, "blocked_count": blocked,
                "quarantined": by_route.get("QUARANTINE", 0),
                "quarantined_count": by_route.get("QUARANTINE", 0),
                "redacted": by_action.get("REDACT", 0) + by_action.get("MASK", 0),
                "flagged_count": total - by_action.get("PASS", 0),
                "unique_users": conn.execute(
                    "SELECT COUNT(DISTINCT user_id) FROM audit_chain").fetchone()[0],
                "block_rate_pct": round(blocked / total * 100, 1),
                "avg_latency_ms": round(avg_lat or 0, 1),
                "avg_risk_input": round(avg_in or 0, 3),
                "avg_risk_output": round(avg_out or 0, 3),
                "by_action": by_action,
                "by_risk_level": grouped("risk_level"),
                "by_category": grouped("category"),
                "by_llm_route": by_route,
                "by_user": grouped("user_id"),
            }

    def get_detection_breakdown(self) -> Dict[str, int]:
        """How many requests contained each entity type (AADHAAR, PAN, ...)."""
        counter: Counter = Counter()
        with closing(self._connect()) as conn:
            for (raw,) in conn.execute("SELECT finding_types FROM audit_chain"):
                try:
                    counter.update(json.loads(raw))
                except Exception:
                    continue
        return dict(counter.most_common())

    def get_timeseries(self, minutes: int = 60, buckets: int = 12) -> List[Dict[str, Any]]:
        """Real request volume over time, split by action - for the live chart."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=minutes)
        width = timedelta(minutes=minutes) / buckets
        series = [
            {"t": (start + width * i).isoformat(), "total": 0, "blocked": 0,
             "redacted": 0, "passed": 0}
            for i in range(buckets)
        ]
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT timestamp, action_taken FROM audit_chain WHERE timestamp >= ?",
                (start.isoformat(),),
            ).fetchall()
        for ts, action in rows:
            try:
                t = datetime.fromisoformat(ts)
            except ValueError:
                continue
            i = min(int((t - start) / width), buckets - 1)
            if i < 0:
                continue
            b = series[i]
            b["total"] += 1
            if action == "BLOCK":
                b["blocked"] += 1
            elif action in ("REDACT", "MASK"):
                b["redacted"] += 1
            else:
                b["passed"] += 1
        return series

    def count(self) -> int:
        with closing(self._connect()) as conn:
            return conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]


# ───────────────────────── quick manual check ─────────────────────────────
if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        lg = HashChainLogger(os.path.join(d, "t.db"), hmac_key="demo")
        lg.log("r1", "user_general", 0.05, 0.0, "CLEAN", "PASS", "PRIMARY", [], "CLEAN", "DEFAULT", 120, "gemini")
        lg.log("r2", "user_hr", 0.7, 0.0, "HIGH", "REDACT", "QUARANTINE",
               [{"type": "SECRET", "subtype": "AADHAAR"}], "PII_LEAKAGE", "PII_REDACT", 310, "qwen3:4b")
        print(lg.verify_chain()["message"])
        print(lg.get_stats()["by_category"])