# gateway/risk_scorer.py
from typing import List, Dict, Any, Tuple
from gateway.models import Finding, RiskAssessment, RiskLevel, PolicyAction

class RiskScorer:
    """
    Calculates a unified Risk Score (0.0 to 1.0) based on detected threats.
    
    Score Mapping:
      0.0 - 0.2  -> CLEAN    (Action: PASS)
      0.2 - 0.4  -> LOW      (Action: WARN)
      0.4 - 0.6  -> MEDIUM   (Action: QUARANTINE - use Qwen local)
      0.6 - 0.8  -> HIGH     (Action: REDACT + QUARANTINE)
      0.8 - 1.0  -> CRITICAL (Action: BLOCK entirely)
    """

    # Base severity weights per threat type
    WEIGHTS = {
        "SECRET": {
            "AWS_ACCESS": 0.95, "AWS_SECRET": 0.95, "PRIVATE_KEY": 0.95,
            "API_KEY": 0.90, "GENERIC_SECRET": 0.85, "JWT_TOKEN": 0.80,
            "AADHAAR": 0.80, "PAN": 0.80, "CREDIT_CARD": 0.85, "PASSWORD": 0.90
        },
        "INJECTION": {
            "INSTRUCTION_OVERRIDE": 0.95, "JAILBREAK": 0.95,
            "SYSTEM_PROMPT_EXTRACT": 0.90, "CONTEXT_MANIPULATION": 0.90,
            "ROLE_HIJACK": 0.85, "DATA_EXTRACTION": 0.80,
            "SOCIAL_ENGINEERING": 0.70, "ML_DETECTED": 0.85
        },
        "PII": {
            "US_SSN": 0.85, "CREDIT_CARD": 0.80,
            "PHONE_NUMBER": 0.40, "EMAIL_ADDRESS": 0.35,
            "PERSON": 0.30, "LOCATION": 0.20, "IP_ADDRESS": 0.40
        }
    }

    def score_input(self, inspection_result: Dict[str, Any]) -> RiskAssessment:
        """Calculates Risk Score 1 for incoming user prompt."""
        findings: List[Finding] = inspection_result.get("findings", [])
        
        if not findings:
            return RiskAssessment(
                score=0.0,
                level=RiskLevel.CLEAN,
                findings=[],
                recommended_action=PolicyAction.PASS,
                details=["No input threats detected"]
            )

        individual_scores = []
        details = []

        for f in findings:
            # Lookup weight or fallback to 0.5
            weight = self.WEIGHTS.get(f.type, {}).get(f.subtype, 0.5)
            effective_score = weight * f.confidence
            individual_scores.append(effective_score)
            details.append(f"{f.type}/{f.subtype}: score {effective_score:.2f}")

        # Base score is the maximum individual score, plus a small boost for multiple findings
        max_score = max(individual_scores) if individual_scores else 0.0
        count_boost = min(len(individual_scores) * 0.05, 0.15)
        final_score = min(max_score + count_boost, 1.0)

        # SECURITY RULE: If prompt injection is detected, enforce a floor score of 0.75
        if inspection_result.get("injection_detected", False):
            final_score = max(final_score, 0.75)
            details.append("Prompt injection detected -> Enforced minimum risk score 0.75")

        level, action = self._score_to_decision(final_score)

        return RiskAssessment(
            score=round(final_score, 3),
            level=level,
            findings=findings,
            recommended_action=action,
            details=details
        )

    def score_output(self, inspection_result: Dict[str, Any]) -> RiskAssessment:
        """Calculates Risk Score 2 for LLM response (stricter scoring)."""
        findings: List[Finding] = inspection_result.get("findings", [])

        if not findings:
            return RiskAssessment(
                score=0.0,
                level=RiskLevel.CLEAN,
                findings=[],
                recommended_action=PolicyAction.PASS,
                details=["Clean output"]
            )

        individual_scores = []
        details = []

        for f in findings:
            weight = self.WEIGHTS.get(f.type, {}).get(f.subtype, 0.5)
            # Output inspection is 20% stricter because model outputs should not contain leaks
            effective_score = min(weight * f.confidence * 1.2, 1.0)
            individual_scores.append(effective_score)
            details.append(f"OUTPUT_{f.type}/{f.subtype}: {effective_score:.2f}")

        max_score = max(individual_scores) if individual_scores else 0.0
        final_score = min(max_score + len(individual_scores) * 0.05, 1.0)

        level, action = self._score_to_decision(final_score)

        return RiskAssessment(
            score=round(final_score, 3),
            level=level,
            findings=findings,
            recommended_action=action,
            details=details
        )

    def _score_to_decision(self, score: float) -> Tuple[RiskLevel, PolicyAction]:
        """Maps numeric risk score to RiskLevel and PolicyAction."""
        if score < 0.2:
            return RiskLevel.CLEAN, PolicyAction.PASS
        elif score < 0.4:
            return RiskLevel.LOW, PolicyAction.WARN
        elif score < 0.6:
            return RiskLevel.MEDIUM, PolicyAction.QUARANTINE
        elif score < 0.8:
            return RiskLevel.HIGH, PolicyAction.REDACT
        else:
            return RiskLevel.CRITICAL, PolicyAction.BLOCK