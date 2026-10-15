# # gateway/pipeline.py
# import uuid
# import time
# from typing import Dict, Any

# from gateway.models import (
#     ChatRequest, ChatResponse, RiskLevel, PolicyAction, LLMRoute
# )
# from gateway.risk_scorer import RiskScorer
# from gateway.policy_engine import PolicyEngine
# from gateway.llm_router import LLMRouter

# # -------------------------------------------------------------------
# # Smart Fallback Imports (Allows Tanya to test before team merges)
# # -------------------------------------------------------------------
# try:
#     from gateway.prompt_inspector import PromptInspector
# except ImportError:
#     class PromptInspector:
#         """Temporary stub until Lakshita's branch is merged."""
#         def inspect(self, text: str) -> Dict[str, Any]:
#             return {
#                 "findings": [],
#                 "pii_count": 0,
#                 "injection_detected": False,
#                 "secrets_found": False,
#                 "sanitized_text": text,
#                 "raw_scores": {"pii_score": 0.0, "injection_score": 0.0, "secret_score": 0.0}
#             }

# try:
#     from gateway.rag_engine import AccessControlledRAG
# except ImportError:
#     class AccessControlledRAG:
#         """Temporary stub until Bhoomi's branch is merged."""
#         def query(self, query_text: str, user_id: str, n_results: int = 3) -> Dict[str, Any]:
#             return {
#                 "context": "",
#                 "allowed_docs": [],
#                 "denied_docs": [],
#                 "access_violation": False
#             }

# try:
#     from gateway.hash_chain import HashChainLogger
# except ImportError:
#     class HashChainLogger:
#         """Temporary stub until Bhoomi's branch is merged."""
#         def log(self, **kwargs) -> str:
#             return "MOCK_HASH_CHAIN_STUB_12345"
#         def get_logs(self, limit: int = 50):
#             return []
#         def get_stats(self):
#             return {"total": 0, "status": "Mock logger active"}
#         def verify_chain(self):
#             return {"valid": True, "entries": 0, "message": "Mock verification"}


# # -------------------------------------------------------------------
# # THE MAIN PIPELINE ORCHESTRATOR
# # -------------------------------------------------------------------
# class GatewayPipeline:
#     """
#     Tanya's Gateway Orchestrator.
#     Flow: User Prompt -> Inspection -> Risk 1 -> Policy -> RAG -> LLM Router -> Response Inspection -> Risk 2 -> Hash Log -> User
#     """

#     def __init__(self):
#         self.inspector = PromptInspector()
#         self.scorer = RiskScorer()
#         self.policy = PolicyEngine()
#         self.rag = AccessControlledRAG()
#         self.llm_router = LLMRouter()
#         self.audit = HashChainLogger()
#         print("🛡️ Gateway Pipeline fully initialized and ready!")

#     async def process(self, request: ChatRequest) -> ChatResponse:
#         request_id = str(uuid.uuid4())
#         actions_taken = []

#         # -----------------------------------------------------------
#         # STAGE 1 & 2: PROMPT INSPECTION & RISK SCORE 1
#         # -----------------------------------------------------------
#         inspection = self.inspector.inspect(request.message)
#         risk1 = self.scorer.score_input(inspection)
#         decision = self.policy.decide(risk1, inspection)

#         actions_taken.extend(decision["reasons"])

#         # Short-circuit if request is BLOCKED
#         if decision["should_block"]:
#             audit_hash = self.audit.log(
#                 request_id=request_id,
#                 user_id=request.user_id,
#                 risk_input=risk1.score,
#                 risk_output=0.0,
#                 risk_level=risk1.level.value,
#                 action=decision["action"].value,
#                 llm_route=LLMRoute.BLOCKED.value,
#                 findings=[f.dict() for f in risk1.findings],
#                 category=self._get_category(risk1.findings),
#                 policy=decision["action"].value,
#                 latency_ms=0.0,
#                 llm_used=LLMRoute.BLOCKED.value
#             )

#             return ChatResponse(
#                 response=f"⛔ Request blocked by AI Security Gateway due to policy violation.\n\nReasons: {'; '.join(decision['reasons'])}",
#                 request_id=request_id,
#                 risk_score_input=risk1.score,
#                 risk_score_output=0.0,
#                 risk_level=risk1.level,
#                 actions_taken=actions_taken,
#                 llm_used=LLMRoute.BLOCKED,
#                 flagged=True,
#                 audit_hash=audit_hash
#             )

#         # -----------------------------------------------------------
#         # STAGE 3: ACCESS-FILTERED RAG RETRIEVAL
#         # -----------------------------------------------------------
#         prompt_to_send = decision["modified_prompt"] or request.message
#         rag_result = self.rag.query(prompt_to_send, request.user_id)

#         if rag_result.get("access_violation", False):
#             denied_titles = [d.get("title", "Restricted Doc") for d in rag_result.get("denied_docs", [])]
#             actions_taken.append(f"ACCESS_DENIED: User '{request.user_id}' lacks permission for documents: {denied_titles}")

#         context = rag_result.get("context", "")

#         # -----------------------------------------------------------
#         # STAGE 4: LLM ROUTING (PRIMARY Gemini vs QUARANTINE Qwen)
#         # -----------------------------------------------------------
#         target_route = decision["llm_route"]
#         actions_taken.append(f"LLM_ROUTED_TO: {target_route.value}")

#         llm_result = await self.llm_router.route_and_call(
#             prompt=prompt_to_send,
#             route=target_route,
#             context=context if context else None
#         )

#         # -----------------------------------------------------------
#         # STAGE 5: RESPONSE INSPECTION & RISK SCORE 2
#         # -----------------------------------------------------------
#         raw_llm_response = llm_result["response"]
#         output_inspection = self.inspector.inspect(raw_llm_response)
#         risk2 = self.scorer.score_output(output_inspection)

#         final_response = raw_llm_response

#         # Sanitize LLM response if PII or secret leaked in output
#         if output_inspection.get("pii_count", 0) > 0 or output_inspection.get("secrets_found", False):
#             final_response = output_inspection.get("sanitized_text", raw_llm_response)
#             actions_taken.append(f"OUTPUT_SANITIZED: Redacted sensitive content from model output.")

#         # -----------------------------------------------------------
#         # STAGE 6: TAMPER-PROOF HASH-CHAIN LOGGING
#         # -----------------------------------------------------------
#         all_findings = [f.dict() for f in risk1.findings] + [f.dict() for f in risk2.findings]

#         audit_hash = self.audit.log(
#             request_id=request_id,
#             user_id=request.user_id,
#             risk_input=risk1.score,
#             risk_output=risk2.score,
#             risk_level=risk1.level.value,
#             action=decision["action"].value,
#             llm_route=llm_result["llm_used"].value,
#             findings=all_findings,
#             category=self._get_category(risk1.findings),
#             policy=decision["action"].value,
#             latency_ms=llm_result["latency_ms"],
#             llm_used=llm_result["llm_used"].value
#         )

#         # -----------------------------------------------------------
#         # STAGE 7: RETURN RESPONSE TO USER
#         # -----------------------------------------------------------
#         is_flagged = (risk1.score > 0.2) or (risk2.score > 0.2) or rag_result.get("access_violation", False)

#         return ChatResponse(
#             response=final_response,
#             request_id=request_id,
#             risk_score_input=risk1.score,
#             risk_score_output=risk2.score,
#             risk_level=risk1.level,
#             actions_taken=actions_taken,
#             llm_used=llm_result["llm_used"],
#             flagged=is_flagged,
#             audit_hash=audit_hash
#         )

#     def _get_category(self, findings: list) -> str:
#         types = set(f.type if hasattr(f, 'type') else f.get('type') for f in findings)
#         if "INJECTION" in types:
#             return "PROMPT_INJECTION"
#         if "SECRET" in types:
#             return "SECRET_EXPOSURE"
#         if "PII" in types:
#             return "PII_LEAKAGE"
#         return "CLEAN"





# gateway/pipeline.py
import uuid
import time
import re
from typing import Dict, Any

from gateway.models import (
    ChatRequest, ChatResponse, RiskLevel, PolicyAction, LLMRoute, Finding
)
from gateway.risk_scorer import RiskScorer
from gateway.policy_engine import PolicyEngine
from gateway.llm_router import LLMRouter

# -------------------------------------------------------------------
# Smart Fallback Imports (Allows Tanya to test before team merges)
# -------------------------------------------------------------------
try:
    from gateway.prompt_inspector import PromptInspector
    print("✅ Lakshita's full PromptInspector loaded")
except ImportError:
    print("⚠️ Using Tanya's temporary mini-detector (Lakshita's branch not merged yet)")
    
    class PromptInspector:
        """Working mini-detector for Tanya's testing (PAN, Aadhaar, API Keys, Tokens, Passwords, IFSC)."""
        
        def inspect(self, text: str) -> Dict[str, Any]:
            findings = []
            sanitized = text

            # 1. Check for API Tokens / Keys / Secrets
            api_key_patterns = [
                r'(?i)(?:api[_-]?(?:token|key)|secret|token|password|passwd|pwd)\s*[:=\-\s]+\s*([a-zA-Z0-9_\-]{16,})',
                r'\b(?:sk-|ak-|api[_-]?key[=:\s]+)[a-zA-Z0-9]{20,}\b',
                r'\bAKIA[0-9A-Z]{16}\b',
                r'\b[a-zA-Z0-9_-]{28,}\b'  # Long random token string
            ]
            
            for pattern in api_key_patterns:
                for match in re.finditer(pattern, text):
                    findings.append({
                        "type": "SECRET", "subtype": "API_KEY", "confidence": 0.95,
                        "start": match.start(), "end": match.end()
                    })
                sanitized = re.sub(pattern, "[API_KEY_REDACTED]", sanitized)

            # 2. Check for PAN Card (e.g., ABCDE1234F)
            pan_pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
            for match in re.finditer(pan_pattern, text):
                findings.append({
                    "type": "SECRET", "subtype": "PAN", "confidence": 0.95,
                    "start": match.start(), "end": match.end()
                })
            sanitized = re.sub(pan_pattern, "[PAN_REDACTED]", sanitized)

            # 3. Check for Aadhaar (e.g., 2345 6789 0123)
            aadhaar_pattern = r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b'
            for match in re.finditer(aadhaar_pattern, text):
                findings.append({
                    "type": "SECRET", "subtype": "AADHAAR", "confidence": 0.95,
                    "start": match.start(), "end": match.end()
                })
            sanitized = re.sub(aadhaar_pattern, "[AADHAAR_REDACTED]", sanitized)

            # 4. Check for IFSC Code (e.g., SBIN0001234)
            ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
            for match in re.finditer(ifsc_pattern, text):
                findings.append({
                    "type": "SECRET", "subtype": "IFSC", "confidence": 0.95,
                    "start": match.start(), "end": match.end()
                })
            sanitized = re.sub(ifsc_pattern, "[IFSC_REDACTED]", sanitized)

            # 5. Check for Indian Phone Numbers
            phone_pattern = r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b'
            for match in re.finditer(phone_pattern, text):
                findings.append({
                    "type": "PII", "subtype": "PHONE_NUMBER", "confidence": 0.85,
                    "start": match.start(), "end": match.end()
                })
            sanitized = re.sub(phone_pattern, "[PHONE_REDACTED]", sanitized)

            # 6. Check for Credit Card Numbers
            cc_pattern = r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'
            for match in re.finditer(cc_pattern, text):
                findings.append({
                    "type": "SECRET", "subtype": "CREDIT_CARD", "confidence": 0.90,
                    "start": match.start(), "end": match.end()
                })
            sanitized = re.sub(cc_pattern, "[CREDIT_CARD_REDACTED]", sanitized)

            # 7. Check for Prompt Injection Keywords
            injection_keywords = [
                "ignore all previous", "ignore previous instructions",
                "disregard instructions", "disregard previous",
                "reveal system prompt", "reveal your prompt",
                "jailbreak", "dan mode", "developer mode",
                "forget everything above", "override your rules",
                "pretend you are", "act as if you are",
                "[inst]", "[system]", "###system", "###instruction"
            ]
            is_injection = any(kw in text.lower() for kw in injection_keywords)
            if is_injection:
                findings.append({
                    "type": "INJECTION", "subtype": "INSTRUCTION_OVERRIDE", "confidence": 0.95
                })

            # Convert dict findings to Finding Pydantic models
            model_findings = [Finding(**f) for f in findings]

            return {
                "findings": model_findings,
                "pii_count": len([f for f in findings if f["type"] in ["PII", "SECRET"]]),
                "injection_detected": is_injection,
                "secrets_found": len([f for f in findings if f["type"] == "SECRET"]) > 0,
                "sanitized_text": sanitized,
                "raw_scores": {
                    "pii_score": 0.8 if findings else 0.0,
                    "injection_score": 0.95 if is_injection else 0.0,
                    "secret_score": 0.90 if findings else 0.0
                }
            }

try:
    from gateway.rag_engine import AccessControlledRAG
    print("✅ Bhoomi's AccessControlledRAG loaded")
except ImportError:
    print("⚠️ Using temporary RAG stub (Bhoomi's branch not merged yet)")
    
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
    print("✅ Bhoomi's HashChainLogger loaded")
except ImportError:
    print("⚠️ Using temporary HashChain stub (Bhoomi's branch not merged yet)")
    
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
        print(f"\n{'='*60}")
        print(f"📨 New Request from user: {request.user_id}")
        print(f"💬 Message: {request.message[:80]}...")
        
        inspection = self.inspector.inspect(request.message)
        print(f"🔍 Inspection: {inspection['pii_count']} PII/Secrets, Injection={inspection['injection_detected']}")
        
        risk1 = self.scorer.score_input(inspection)
        print(f"📊 Input Risk Score: {risk1.score} ({risk1.level.value})")
        
        decision = self.policy.decide(risk1, inspection)
        print(f"⚖️ Policy Decision: {decision['action'].value} → Route: {decision['llm_route'].value}")

        actions_taken.extend(decision["reasons"])

        # Short-circuit if request is BLOCKED
        if decision["should_block"]:
            print("🛑 Request BLOCKED - returning without calling LLM")
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
                response=f"⛔ Request blocked by AI Security Gateway due to policy violation.\n\nReasons: {'; '.join(decision['reasons'][:3])}",
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
        print(f"📊 Output Risk Score: {risk2.score} ({risk2.level.value})")

        final_response = raw_llm_response

        # Sanitize LLM response if PII or secret leaked in output
        if output_inspection.get("pii_count", 0) > 0 or output_inspection.get("secrets_found", False):
            final_response = output_inspection.get("sanitized_text", raw_llm_response)
            actions_taken.append(f"OUTPUT_SANITIZED: Redacted sensitive content from model output.")
            print(f"✂️ Output sanitized - removed {output_inspection['pii_count']} sensitive items")

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
        
        print(f"✅ Request complete | Flagged: {is_flagged} | LLM: {llm_result['llm_used'].value}")
        print(f"{'='*60}\n")

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
        """Determine the primary category of threats found."""
        types = set(f.type if hasattr(f, 'type') else f.get('type') for f in findings)
        if "INJECTION" in types:
            return "PROMPT_INJECTION"
        if "SECRET" in types:
            return "SECRET_EXPOSURE"
        if "PII" in types:
            return "PII_LEAKAGE"
        return "CLEAN"