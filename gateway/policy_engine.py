# gateway/policy_engine.py
from typing import Dict, Any, List
from gateway.models import PolicyAction, RiskAssessment, LLMRoute

class PolicyEngine:
    """Configurable security policy decision engine."""

    def __init__(self):
        # Default policies
        self.policies = {
            "pii_in_prompt":     {"action": "redact", "threshold": 0.4},
            "secrets_in_prompt": {"action": "block",  "threshold": 0.5},
            "prompt_injection":  {"action": "block",  "threshold": 0.6},
            "pii_in_response":   {"action": "redact", "threshold": 0.4},
        }

        # Routing thresholds
        self.quarantine_threshold = 0.4  # Score > 0.4 -> Local Qwen
        self.block_threshold = 0.8       # Score > 0.8 -> Block entirely

    def decide(self, risk: RiskAssessment, inspection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Makes the final security and routing decision.
        """
        action = risk.recommended_action
        reasons = list(risk.details)
        should_block = False
        llm_route = LLMRoute.PRIMARY

        # Rule 1: Direct Prompt Injection -> BLOCK
        if inspection_result.get("injection_detected", False):
            if self.policies["prompt_injection"]["action"] == "block":
                return self._build_decision(
                    action=PolicyAction.BLOCK,
                    llm_route=LLMRoute.BLOCKED,
                    modified_prompt=None,
                    reasons=reasons + ["POLICY: Prompt injection detected -> BLOCK"],
                    should_block=True
                )

        # Rule 2: Hard Secrets/Credentials -> BLOCK
        if inspection_result.get("secrets_found", False):
            if self.policies["secrets_in_prompt"]["action"] == "block":
                return self._build_decision(
                    action=PolicyAction.BLOCK,
                    llm_route=LLMRoute.BLOCKED,
                    modified_prompt=None,
                    reasons=reasons + ["POLICY: Secrets/Credentials detected -> BLOCK"],
                    should_block=True
                )

        # Rule 3: Score-based LLM Routing
        if risk.score >= self.block_threshold:
            should_block = True
            action = PolicyAction.BLOCK
            llm_route = LLMRoute.BLOCKED
            reasons.append(f"ROUTING: Risk score {risk.score} >= Block threshold ({self.block_threshold})")

        elif risk.score >= self.quarantine_threshold:
            llm_route = LLMRoute.QUARANTINE
            reasons.append(f"ROUTING: Risk score {risk.score} >= Quarantine threshold ({self.quarantine_threshold}) -> Routed to Local Qwen")
            if inspection_result.get("pii_count", 0) > 0:
                action = PolicyAction.REDACT
                reasons.append("POLICY: PII present -> Prompt sanitized before sending to local model")
        else:
            llm_route = LLMRoute.PRIMARY
            if inspection_result.get("pii_count", 0) > 0:
                action = PolicyAction.REDACT
                reasons.append("POLICY: Mild PII present -> Prompt sanitized before sending to Gemini")

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