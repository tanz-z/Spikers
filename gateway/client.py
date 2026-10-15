"""
gateway/client.py - the ONE door the UIs use to talk to the security gateway
Owner: Bhoomi

    client = GatewayClient()
    result = client.chat("user_hr", "What is the holiday calendar?")

LIVE mode : POSTs to Tanya's FastAPI gateway (GATEWAY_URL, default http://localhost:8000/chat).
DEMO mode : if the API is unreachable, runs a local stand-in (real regex detection +
            real access-controlled RAG + real hash-chain logging) so the UI is fully
            usable before the pipeline is merged. The UI code never changes.

Every result has the same shape (the ChatResponse contract + a few UI helpers):
    response, request_id, risk_score_input, risk_score_output, risk_level,
    actions_taken, llm_used, flagged, audit_hash,
    status   -> "SAFE" | "MASKED" | "RESTRICTED" | "BLOCKED"   (what the END USER may see)
    mode     -> "live" | "demo"
    findings -> [{"type","subtype"}]            (admin-only detail, demo mode)
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

DEFAULT_URL = "http://localhost:8000"

# ───────────────────────── local detection (demo mode) ─────────────────────────
# (type, subtype, regex, weight). Order matters: earlier patterns claim their text first.
_SECRETS: List[Tuple[str, str, str, float]] = [
    ("SECRET", "PRIVATE_KEY", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", 0.95),
    ("SECRET", "AWS_ACCESS", r"\bAKIA[0-9A-Z]{16}\b", 0.90),
    ("SECRET", "JWT_TOKEN", r"eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]+", 0.80),
    ("SECRET", "API_KEY", r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*[\"']?[\w\-]{16,}", 0.85),
    ("SECRET", "GENERIC_SECRET", r"(?i)\b(?:password|passwd|pwd)\s*(?:is|[=:])\s*[\"']?\S{6,}", 0.80),
    ("SECRET", "CREDIT_CARD", r"\b(?:\d{4}[\s-]?){3}\d{4}\b", 0.75),
]
_PII: List[Tuple[str, str, str, float]] = [
    ("PII", "PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.70),
    ("PII", "AADHAAR", r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b", 0.70),
    ("PII", "INDIAN_PHONE", r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)", 0.40),
    ("PII", "EMAIL_ADDRESS", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", 0.35),
]
_INJECTION: List[Tuple[str, str, float]] = [
    ("INSTRUCTION_OVERRIDE", r"(?i)\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|above|prior|your|the|system)\s+(instructions|prompts|rules|guidelines|constraints)", 0.95),
    ("SYSTEM_PROMPT_EXTRACT", r"(?i)\b(reveal|show|display|print|output|repeat|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules|configuration)", 0.90),
    ("JAILBREAK", r"(?i)\b(jailbreak|DAN\s+mode|developer\s+mode|god\s+mode|no\s+filter|unrestricted\s+mode)", 0.95),
    ("ROLE_HIJACK", r"(?i)\b(you\s+are\s+now|pretend\s+(to\s+be|you\s+are))\b.{0,30}(mode|persona|character|AI|assistant)", 0.85),
    ("CONTEXT_MANIPULATION", r"(?i)(\[INST\]|\[SYSTEM\]|<\|im_start\|>|###\s*(INSTRUCTION|SYSTEM))", 0.90),
    ("DATA_EXTRACTION", r"(?i)\b(dump|extract|list)\s+(all\s+)?(user|customer|employee|confidential|secret|restricted)\s+(data|info|records|credentials)", 0.75),
]


def inspect_text(text: str) -> Dict[str, Any]:
    """Regex inspection. Returns findings + sanitized text. Raw values are never kept."""
    claimed: List[Tuple[int, int]] = []
    findings: List[Dict[str, Any]] = []
    spans: List[Tuple[int, int, str]] = []

    def free(s: int, e: int) -> bool:
        return all(e <= a or s >= b for a, b in claimed)

    for typ, sub, pat, weight in _SECRETS + _PII:
        for m in re.finditer(pat, text):
            if free(m.start(), m.end()):
                claimed.append((m.start(), m.end()))
                spans.append((m.start(), m.end(), sub))
                findings.append({"type": typ, "subtype": sub, "weight": weight})

    for sub, pat, weight in _INJECTION:
        if re.search(pat, text):
            findings.append({"type": "INJECTION", "subtype": sub, "weight": weight})

    sanitized = text
    for s, e, sub in sorted(spans, reverse=True):
        sanitized = f"{sanitized[:s]}[{sub}_REDACTED]{sanitized[e:]}"
    return {"findings": findings, "sanitized": sanitized}


def score_findings(findings: List[Dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    top = max(f["weight"] for f in findings)
    score = min(top + min(len(findings) * 0.05, 0.15), 1.0)
    if any(f["type"] == "INJECTION" for f in findings):
        score = max(score, 0.7)
    return round(score, 3)


def _level(score: float) -> str:
    return ("CRITICAL" if score >= 0.8 else "HIGH" if score >= 0.6 else
            "MEDIUM" if score >= 0.4 else "LOW" if score >= 0.2 else "CLEAN")


def derive_status(llm_used: str, actions: List[str]) -> str:
    """What the end user is allowed to know: safe / masked / blocked."""
    if str(llm_used).upper() == "BLOCKED":
        return "BLOCKED"
    joined = " ".join(actions).upper()
    if any(k in joined for k in ("REDACT", "SANITIZ", "MASK")):
        return "MASKED"
    return "RESTRICTED" if "ACCESS_CONTROL" in joined else "SAFE"


# ───────────────────────────────── client ─────────────────────────────────────
class GatewayClient:
    def __init__(self, base_url: Optional[str] = None, rag: Any = None,
                 logger: Any = None, timeout: float = 90.0, force_demo: bool = False):
        self.base_url = (base_url or os.getenv("GATEWAY_URL") or DEFAULT_URL).rstrip("/")
        self.timeout = timeout
        self.force_demo = force_demo or os.getenv("GATEWAY_MODE", "").lower() == "demo"
        self._rag = rag
        self._logger = logger
        self.last_error: Optional[str] = None

    # lazy so importing this module never needs chromadb
    @property
    def rag(self):
        if self._rag is None:
            from gateway.rag_engine import AccessControlledRAG
            self._rag = AccessControlledRAG()
        return self._rag

    @property
    def logger(self):
        if self._logger is None:
            from gateway.hash_chain import HashChainLogger
            self._logger = HashChainLogger()
        return self._logger

    def is_live(self) -> bool:
        if self.force_demo:
            return False
        try:
            with urllib.request.urlopen(f"{self.base_url}/health", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def chat(self, user_id: str, message: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        if not self.force_demo:
            try:
                return self._chat_live(user_id, message, session_id)
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                self.last_error = f"{type(e).__name__}: {e}"
        return self._chat_demo(user_id, message)

    # ── live ──
    def _chat_live(self, user_id: str, message: str, session_id: Optional[str]) -> Dict[str, Any]:
        body = json.dumps({"user_id": user_id, "message": message, "session_id": session_id}).encode()
        req = urllib.request.Request(f"{self.base_url}/chat", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        data.setdefault("findings", [])
        data["status"] = derive_status(data.get("llm_used", ""), data.get("actions_taken", []))
        data["mode"] = "live"
        return data

    # ── demo ──
    def _chat_demo(self, user_id: str, message: str) -> Dict[str, Any]:
        t0 = time.time()
        request_id = str(uuid.uuid4())
        insp = inspect_text(message)
        findings = insp["findings"]
        types = {f["type"] for f in findings}
        score = score_findings(findings)
        actions: List[str] = []
        category, action, route = "CLEAN", "PASS", "PRIMARY"
        policy = "DEFAULT"

        if "INJECTION" in types:
            category, action, route, policy = "PROMPT_INJECTION", "BLOCK", "BLOCKED", "PROMPT_INJECTION_BLOCK"
        elif "SECRET" in types:
            category, action, route, policy = "SECRET", "BLOCK", "BLOCKED", "SECRETS_BLOCK"
        elif score > 0.8:
            category, action, route, policy = "PII", "BLOCK", "BLOCKED", "SCORE_BLOCK"
        elif "PII" in types:
            category, policy = "PII", "PII_REDACT"
            action, route = ("REDACT", "QUARANTINE") if score > 0.4 else ("WARN", "PRIMARY")
            actions.append(f"POLICY: PII found -> sanitized prompt used ({route})")

        rag_res: Dict[str, Any] = {"context": "", "allowed_docs": [], "access_violation": False}
        if route != "BLOCKED":
            rag_res = self.rag.query(insp["sanitized"], user_id)
            if rag_res["access_violation"] and not rag_res["allowed_docs"]:
                category, action, route, policy = "ACCESS_VIOLATION", "BLOCK", "BLOCKED", "RBAC_DENY"
                score = max(score, 0.8)
                findings.append({"type": "ACCESS", "subtype": "UNAUTHORIZED_DOC", "weight": 0.8})
                actions.append("ACCESS_CONTROL: restricted documents denied for this role")
            elif rag_res["access_violation"]:
                # Partial denial: answer from allowed docs, but the attempt MUST be visible to the admin.
                if action == "PASS":
                    category, action, policy = "ACCESS_VIOLATION", "WARN", "RBAC_PARTIAL"
                score = max(score, 0.5)
                findings.append({"type": "ACCESS", "subtype": "UNAUTHORIZED_DOC", "weight": 0.5})
                actions.append("ACCESS_CONTROL: some restricted documents were withheld")

        if route == "BLOCKED":
            actions.insert(0, f"POLICY: {policy} -> BLOCK")
            reply = ("This request was blocked by your organisation's security policy. "
                     "If you believe this is a mistake, contact your IT administrator.")
            llm_used = "BLOCKED"
        else:
            ctx = rag_res["context"].strip()
            notice = ("Part of your request involves information that is restricted for your role, "
                      "so it was left out.\n\n" if rag_res["access_violation"] else "")
            reply = notice + (f"Here is what I found in the documents you have access to:\n\n{ctx[:600]}"
                              if ctx else
                              "I couldn't find anything relevant in the documents available to you.")
            llm_used = "demo-retrieval"
            actions.append(f"LLM_ROUTE: {route}")

        latency = 0.0 if route == "BLOCKED" else (time.time() - t0) * 1000
        audit_hash = self.logger.log(
            request_id=request_id, user_id=user_id, risk_input=score, risk_output=0.0,
            risk_level=_level(score), action=action, llm_route=route, findings=findings,
            category=category, policy=policy, latency_ms=latency, llm_used=llm_used)

        return {
            "response": reply, "request_id": request_id,
            "risk_score_input": score, "risk_score_output": 0.0, "risk_level": _level(score),
            "actions_taken": actions, "llm_used": llm_used,
            "flagged": score > 0.2 or rag_res["access_violation"],
            "audit_hash": audit_hash,
            "status": derive_status(llm_used, actions + ([f"{action}"] if action in ("REDACT", "MASK") else [])),
            "mode": "demo",
            "findings": [{"type": f["type"], "subtype": f["subtype"]} for f in findings],
        }
