# gateway/models.py
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

class RiskLevel(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class PolicyAction(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    MASK = "MASK"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"

class LLMRoute(str, Enum):
    PRIMARY = "PRIMARY"       # Gemini API
    QUARANTINE = "QUARANTINE" # Qwen2.5 (Local)
    BLOCKED = "BLOCKED"       # No call

class Finding(BaseModel):
    type: str                # PII, SECRET, or INJECTION
    subtype: str             # AADHAAR, PAN, INSTRUCTION_OVERRIDE, etc.
    confidence: float        # 0.0 to 1.0
    start: Optional[int] = None
    end: Optional[int] = None

class RiskAssessment(BaseModel):
    score: float             # 0.0 to 1.0
    level: RiskLevel
    findings: List[Finding] = []
    recommended_action: PolicyAction
    details: List[str] = []

class ChatRequest(BaseModel):
    user_id: str
    message: str
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    request_id: str
    risk_score_input: float
    risk_score_output: float
    risk_level: RiskLevel
    actions_taken: List[str]
    llm_used: LLMRoute
    flagged: bool
    audit_hash: str