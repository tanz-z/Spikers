"""
scripts/demo_tools.py - seed realistic audit data and stage tamper attacks for the demo.

Run from the project root (venv active):
    python -m scripts.demo_tools seed --reset     # 60 realistic entries over the last 24h
    python -m scripts.demo_tools verify           # integrity report
    python -m scripts.demo_tools backup           # snapshot the clean ledger
    python -m scripts.demo_tools tamper           # attacker edits a BLOCK row to look harmless
    python -m scripts.demo_tools delete-middle    # attacker deletes a row to hide it
    python -m scripts.demo_tools truncate         # attacker chops off the newest rows
    python -m scripts.demo_tools rollback         # attacker restores an older (valid) copy
    python -m scripts.demo_tools restore          # back to the clean snapshot
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.hash_chain import DB_PATH, HashChainLogger  # noqa: E402
from gateway.integrity import RECEIPT_PATH, check_integrity  # noqa: E402

BACKUP = DB_PATH.replace(".db", ".clean.db")
OLD_COPY = DB_PATH.replace(".db", ".old.db")

# (category, action, route, llm_used, risk range, findings, weight)
SCENARIOS = [
    ("CLEAN", "PASS", "PRIMARY", "gemini-1.5-flash", (0.02, 0.15), [], 46),
    ("PII", "REDACT", "QUARANTINE", "qwen3:4b", (0.55, 0.78), [{"subtype": "AADHAAR"}], 9),
    ("PII", "REDACT", "QUARANTINE", "qwen3:4b", (0.50, 0.72), [{"subtype": "PAN"}, {"subtype": "INDIAN_PHONE"}], 6),
    ("PII", "WARN", "PRIMARY", "gemini-1.5-flash", (0.25, 0.38), [{"subtype": "EMAIL_ADDRESS"}], 7),
    ("SECRET", "BLOCK", "BLOCKED", "none", (0.88, 0.97), [{"subtype": "AWS_ACCESS"}], 4),
    ("SECRET", "BLOCK", "BLOCKED", "none", (0.85, 0.95), [{"subtype": "GENERIC_SECRET"}], 3),
    ("PROMPT_INJECTION", "BLOCK", "BLOCKED", "none", (0.90, 0.98), [{"subtype": "INSTRUCTION_OVERRIDE"}], 8),
    ("PROMPT_INJECTION", "BLOCK", "BLOCKED", "none", (0.88, 0.96), [{"subtype": "JAILBREAK"}], 4),
    ("ACCESS_VIOLATION", "BLOCK", "BLOCKED", "none", (0.78, 0.90), [{"subtype": "UNAUTHORIZED_DOC"}], 6),
    ("PROMPT_INJECTION", "QUARANTINE", "QUARANTINE", "qwen3:4b", (0.45, 0.58), [{"subtype": "SOCIAL_ENGINEERING"}], 5),
]
USERS = ["user_general", "user_hr", "user_finance", "user_devops", "user_cfo", "user_admin"]


def _reset_files() -> None:
    for p in (DB_PATH, DB_PATH + "-wal", DB_PATH + "-shm", RECEIPT_PATH):
        if os.path.exists(p):
            os.remove(p)


def cmd_seed(args) -> None:
    lg = HashChainLogger()
    if args.reset:
        _reset_files()
        lg = HashChainLogger()
    if lg.count() and not args.reset:
        sys.exit("Ledger is not empty. Use --reset to wipe it first.")

    rnd = random.Random(7)  # deterministic: same demo data every time
    now = datetime.now(timezone.utc)
    stamps = sorted(now - timedelta(minutes=rnd.uniform(1, 24 * 60)) for _ in range(args.n))
    weights = [s[-1] for s in SCENARIOS]

    for i, ts in enumerate(stamps):
        cat, action, route, llm, (lo, hi), findings, _ = rnd.choices(SCENARIOS, weights)[0]
        risk = round(rnd.uniform(lo, hi), 3)
        level = ("CRITICAL" if risk >= .8 else "HIGH" if risk >= .6 else
                 "MEDIUM" if risk >= .4 else "LOW" if risk >= .2 else "CLEAN")
        lg.log(request_id=f"seed_{i:04d}", user_id=rnd.choice(USERS), risk_input=risk,
               risk_output=round(rnd.uniform(0, .1), 3) if action != "BLOCK" else 0.0,
               risk_level=level, action=action, llm_route=route, findings=findings,
               category=cat, policy=f"{action}_POLICY",
               latency_ms=0 if action == "BLOCK" else round(rnd.uniform(180, 1400), 1),
               llm_used=llm, timestamp=ts.isoformat())
    print(f"Seeded {lg.count()} entries.")
    cmd_verify(args)


def cmd_verify(_args) -> None:
    rep = check_integrity(HashChainLogger())
    print(f"\n  STATUS : {rep['status']}   ({rep['entries']} entries, head #{rep['head_seq']})")
    for a in rep["alerts"]:
        print(f"  ALERT  : [{a['type']}] {a['detail']}")
    if rep["status"] == "SECURE":
        print("  Every row, link, signature and the head anchor verified.")
    print()


def _exec(sql: str, params=()) -> None:
    c = sqlite3.connect(DB_PATH)
    c.execute(sql, params)
    c.commit()
    c.close()


def _pick(sql: str):
    c = sqlite3.connect(DB_PATH)
    row = c.execute(sql).fetchone()
    c.close()
    return row


def cmd_backup(_args) -> None:
    c = sqlite3.connect(DB_PATH)
    c.execute("PRAGMA wal_checkpoint(FULL)")
    c.close()
    shutil.copyfile(DB_PATH, BACKUP)
    print(f"Clean snapshot saved -> {BACKUP}")


def cmd_restore(_args) -> None:
    if not os.path.exists(BACKUP):
        sys.exit("No snapshot found. Run `backup` first.")
    for p in (DB_PATH + "-wal", DB_PATH + "-shm"):
        if os.path.exists(p):
            os.remove(p)
    shutil.copyfile(BACKUP, DB_PATH)
    print("Ledger restored to the clean snapshot.")


def cmd_tamper(_args) -> None:
    row = _pick("SELECT seq FROM audit_chain WHERE action_taken='BLOCK' ORDER BY seq DESC LIMIT 1 OFFSET 2")
    if not row:
        sys.exit("No BLOCK row to tamper with. Seed first.")
    _exec("UPDATE audit_chain SET action_taken='PASS', risk_score_input=0.03, risk_level='CLEAN', "
          "category='CLEAN' WHERE seq=?", (row[0],))
    print(f"Attacker rewrote record #{row[0]} (BLOCK -> PASS) to hide an incident.")


def cmd_delete_middle(_args) -> None:
    row = _pick("SELECT seq FROM audit_chain ORDER BY seq DESC LIMIT 1 OFFSET 6")
    _exec("DELETE FROM audit_chain WHERE seq=?", (row[0],))
    print(f"Attacker deleted record #{row[0]}.")


def cmd_truncate(_args) -> None:
    _exec("DELETE FROM audit_chain WHERE seq > (SELECT MAX(seq) - 3 FROM audit_chain)")
    print("Attacker removed the 3 newest records.")


def cmd_rollback(_args) -> None:
    """Replace the DB with an older, internally-valid copy (needs `backup` taken earlier)."""
    if not os.path.exists(BACKUP):
        sys.exit("Take a `backup` BEFORE generating new traffic, then run rollback after.")
    shutil.copyfile(BACKUP, DB_PATH)
    for p in (DB_PATH + "-wal", DB_PATH + "-shm"):
        if os.path.exists(p):
            os.remove(p)
    print("Attacker restored an older copy of the ledger (it is internally valid!).")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed")
    s.add_argument("--n", type=int, default=60)
    s.add_argument("--reset", action="store_true")
    s.set_defaults(fn=cmd_seed)
    for name, fn in (("verify", cmd_verify), ("backup", cmd_backup), ("restore", cmd_restore),
                     ("tamper", cmd_tamper), ("delete-middle", cmd_delete_middle),
                     ("truncate", cmd_truncate), ("rollback", cmd_rollback)):
        sub.add_parser(name).set_defaults(fn=fn)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
