# gateway/policy_engine.py
from typing import Dict, Any, List
from gateway.models import PolicyAction, RiskAssessment, LLMRoute

class PolicyEngine:
    """Configurable security policy decision engine."""

    def __init__(self):
        # Updated Default Policies based on enterprise best practices
        self.policies = {
            "pii_in_prompt":     {"action": "redact"},
            "secrets_in_prompt": {"action": "redact"},  # Changed from block to redact
            "prompt_injection":  {"action": "block"},   # Injections still get blocked
            "pii_in_response":   {"action": "redact"},
        }

    def decide(self, risk: RiskAssessment, inspection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates findings and makes routing decisions.
        New Logic: If secrets/PII are found, they are masked, making the prompt safe for Gemini.
        """
        action = PolicyAction.PASS
        reasons = list(risk.details)
        should_block = False
        llm_route = LLMRoute.PRIMARY # Default to Gemini

        # Rule 1: Prompt Injection -> Hard BLOCK (cannot be masked)
        if inspection_result.get("injection_detected", False):
            if self.policies["prompt_injection"]["action"] == "block":
                return self._build_decision(
                    action=PolicyAction.BLOCK,
                    llm_route=LLMRoute.BLOCKED,
                    modified_prompt=None,
                    reasons=reasons + ["POLICY: Prompt injection detected -> Request Blocked"],
                    should_block=True
                )

        # Rule 2: Secrets or PII Detected -> MASK & Send to Gemini
        if inspection_result.get("secrets_found", False) or inspection_result.get("pii_count", 0) > 0:
            action = PolicyAction.REDACT
            reasons.append("POLICY: Sensitive Data Detected -> Prompt masked/sanitized.")
            reasons.append("ROUTING: Sanitized prompt is safe -> Routed to Primary LLM (Gemini).")
            # We keep llm_route as PRIMARY because the text is now safe!

        modified_prompt = inspection_result.get("sanitized_text", None)

        return self._build_decision(action, llm_route, modified_prompt, reasons, should_block)

    def _build_decision(self, action: PolicyAction, llm_route: LLMRoute,
                        modified_prompt: str, reasons: List[str], should_block: bool) -> Dict[str, Any]:
        return {
            "action": action,
            "llm_route": llm_route,
            "modified_prompt": modified_prompt,
            "reasons": reasons,
            "should_block": should_block
        }

    def update_policy(self, policy_name: str, new_action: str):
        if policy_name in self.policies:
            self.policies[policy_name]["action"] = new_action

    def get_all_policies(self) -> Dict[str, Any]:
        return self.policies