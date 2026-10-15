# gateway/pipeline.py
import uuid
import time
from typing import Dict, Any

from gateway.models import (
    ChatRequest, ChatResponse, RiskLevel, PolicyAction, LLMRoute
)
from gateway.risk_scorer import RiskScorer
from gateway.policy_engine import PolicyEngine
from gateway.llm_router import LLMRouter

# -------------------------------------------------------------------
# Smart Fallback Imports (Allows Tanya to test before team merges)
# -------------------------------------------------------------------
try:
    from gateway.prompt_inspector import PromptInspector
except ImportError:
    class PromptInspector:
        """Temporary stub until Lakshita's branch is merged."""
        def inspect(self, text: str) -> Dict[str, Any]:
            return {
                "findings": [],
                "pii_count": 0,
                "injection_detected": False,
                "secrets_found": False,
                "sanitized_text": text,
                "raw_scores": {"pii_score": 0.0, "injection_score": 0.0, "secret_score": 0.0}
            }

try:
    from gateway.rag_engine import AccessControlledRAG
except ImportError:
    class AccessControlledRAG:
        """Temporary stub until Bhoomi's branch is merged."""
        def query(self, query_text: str, user_id: str, n_results: int = 3) -> Dict[str, Any]:
            return {
                "context": "",
                "allowed_docs": [],
                "denied_docs": [],
                "access_violation": False
            }

try:
    from gateway.hash_chain import HashChainLogger
except ImportError:
    class HashChainLogger:
        """Temporary stub until Bhoomi's branch is merged."""
        def log(self, **kwargs) -> str:
            return "MOCK_HASH_CHAIN_STUB_12345"
        def get_logs(self, limit: int = 50):
            return []
        def get_stats(self):
            return {"total": 0, "status": "Mock logger active"}
        def verify_chain(self):
            return {"valid": True, "entries": 0, "message": "Mock verification"}


# -------------------------------------------------------------------
# THE MAIN PIPELINE ORCHESTRATOR
# -------------------------------------------------------------------
class GatewayPipeline:
    """
    Tanya's Gateway Orchestrator.
    Flow: User Prompt -> Inspection -> Risk 1 -> Policy -> RAG -> LLM Router -> Response Inspection -> Risk 2 -> Hash Log -> User
    """

    def __init__(self):
        self.inspector = PromptInspector()
        self.scorer = RiskScorer()
        self.policy = PolicyEngine()
        self.rag = AccessControlledRAG()
        self.llm_router = LLMRouter()
        self.audit = HashChainLogger()
        print("🛡️ Gateway Pipeline fully initialized and ready!")

    async def process(self, request: ChatRequest) -> ChatResponse:
        request_id = str(uuid.uuid4())
        actions_taken = []

        # -----------------------------------------------------------
        # STAGE 1 & 2: PROMPT INSPECTION & RISK SCORE 1
        # -----------------------------------------------------------
        inspection = self.inspector.inspect(request.message)
        risk1 = self.scorer.score_input(inspection)
        decision = self.policy.decide(risk1, inspection)

        actions_taken.extend(decision["reasons"])

        # Short-circuit if request is BLOCKED
        if decision["should_block"]:
            audit_hash = self.audit.log(
                request_id=request_id,
                user_id=request.user_id,
                risk_input=risk1.score,
                risk_output=0.0,
                risk_level=risk1.level.value,
                action=decision["action"].value,
                llm_route=LLMRoute.BLOCKED.value,
                findings=[f.dict() for f in risk1.findings],
                category=self._get_category(risk1.findings),
                policy=decision["action"].value,
                latency_ms=0.0,
                llm_used=LLMRoute.BLOCKED.value
            )

            return ChatResponse(
                response=f"⛔ Request blocked by AI Security Gateway due to policy violation.\n\nReasons: {'; '.join(decision['reasons'])}",
                request_id=request_id,
                risk_score_input=risk1.score,
                risk_score_output=0.0,
                risk_level=risk1.level,
                actions_taken=actions_taken,
                llm_used=LLMRoute.BLOCKED,
                flagged=True,
                audit_hash=audit_hash
            )

        # -----------------------------------------------------------
        # STAGE 3: ACCESS-FILTERED RAG RETRIEVAL
        # -----------------------------------------------------------
        prompt_to_send = decision["modified_prompt"] or request.message
        rag_result = self.rag.query(prompt_to_send, request.user_id)

        if rag_result.get("access_violation", False):
            denied_titles = [d.get("title", "Restricted Doc") for d in rag_result.get("denied_docs", [])]
            actions_taken.append(f"ACCESS_DENIED: User '{request.user_id}' lacks permission for documents: {denied_titles}")

        context = rag_result.get("context", "")

        # -----------------------------------------------------------
        # STAGE 4: LLM ROUTING (PRIMARY Gemini vs QUARANTINE Qwen)
        # -----------------------------------------------------------
        target_route = decision["llm_route"]
        actions_taken.append(f"LLM_ROUTED_TO: {target_route.value}")

        llm_result = await self.llm_router.route_and_call(
            prompt=prompt_to_send,
            route=target_route,
            context=context if context else None
        )

        # -----------------------------------------------------------
        # STAGE 5: RESPONSE INSPECTION & RISK SCORE 2
        # -----------------------------------------------------------
        raw_llm_response = llm_result["response"]
        output_inspection = self.inspector.inspect(raw_llm_response)
        risk2 = self.scorer.score_output(output_inspection)

        final_response = raw_llm_response

        # Sanitize LLM response if PII or secret leaked in output
        if output_inspection.get("pii_count", 0) > 0 or output_inspection.get("secrets_found", False):
            final_response = output_inspection.get("sanitized_text", raw_llm_response)
            actions_taken.append(f"OUTPUT_SANITIZED: Redacted sensitive content from model output.")

        # -----------------------------------------------------------
        # STAGE 6: TAMPER-PROOF HASH-CHAIN LOGGING
        # -----------------------------------------------------------
        all_findings = [f.dict() for f in risk1.findings] + [f.dict() for f in risk2.findings]

        audit_hash = self.audit.log(
            request_id=request_id,
            user_id=request.user_id,
            risk_input=risk1.score,
            risk_output=risk2.score,
            risk_level=risk1.level.value,
            action=decision["action"].value,
            llm_route=llm_result["llm_used"].value,
            findings=all_findings,
            category=self._get_category(risk1.findings),
            policy=decision["action"].value,
            latency_ms=llm_result["latency_ms"],
            llm_used=llm_result["llm_used"].value
        )

        # -----------------------------------------------------------
        # STAGE 7: RETURN RESPONSE TO USER
        # -----------------------------------------------------------
        is_flagged = (risk1.score > 0.2) or (risk2.score > 0.2) or rag_result.get("access_violation", False)

        return ChatResponse(
            response=final_response,
            request_id=request_id,
            risk_score_input=risk1.score,
            risk_score_output=risk2.score,
            risk_level=risk1.level,
            actions_taken=actions_taken,
            llm_used=llm_result["llm_used"],
            flagged=is_flagged,
            audit_hash=audit_hash
        )

    def _get_category(self, findings: list) -> str:
        types = set(f.type if hasattr(f, 'type') else f.get('type') for f in findings)
        if "INJECTION" in types:
            return "PROMPT_INJECTION"
        if "SECRET" in types:
            return "SECRET_EXPOSURE"
        if "PII" in types:
            return "PII_LEAKAGE"
        return "CLEAN"