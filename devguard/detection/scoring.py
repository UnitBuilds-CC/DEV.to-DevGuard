from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class DetectionFlag(BaseModel):
    detector: str
    rule_name: str
    severity: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    username: str
    user_id: Optional[int] = None
    risk_score: float = 0.0  # 0.0 to 1.0
    verdict: str = "clean"  # clean, suspicious, likely_bot, confirmed_bot
    flags: List[DetectionFlag] = Field(default_factory=list)
    confidence: str = "low"  # low, medium, high

    def compute_composite_verdict(
        self, 
        weights: Dict[str, float], 
        thresholds: Dict[str, float]
    ) -> None:
        """Computes the final risk score and verdict based on active flags and layer weights."""
        if not self.flags:
            self.risk_score = 0.0
            self.verdict = "clean"
            self.confidence = "high"
            return

        # Group severity by detector
        detector_max_severities = {}
        for flag in self.flags:
            detector = flag.detector
            if detector not in detector_max_severities:
                detector_max_severities[detector] = 0.0
            detector_max_severities[detector] = max(detector_max_severities[detector], flag.severity)

        # Compute weighted sum
        total_weight = 0.0
        weighted_score = 0.0
        for detector, severity in detector_max_severities.items():
            weight = weights.get(detector, 0.2)
            weighted_score += severity * weight
            total_weight += weight

        if total_weight > 0:
            self.risk_score = min(1.0, weighted_score / total_weight)
        else:
            self.risk_score = 0.0

        # Assign verdict based on thresholds
        if self.risk_score >= thresholds.get("confirmed_bot", 0.9):
            self.verdict = "confirmed_bot"
        elif self.risk_score >= thresholds.get("likely_bot", 0.7):
            self.verdict = "likely_bot"
        elif self.risk_score >= thresholds.get("suspicious", 0.4):
            self.verdict = "suspicious"
        else:
            self.verdict = "clean"

        # Determine confidence based on number of distinct detectors firing
        unique_detectors = len(detector_max_severities)
        if unique_detectors >= 3:
            self.confidence = "high"
        elif unique_detectors >= 2:
            self.confidence = "medium"
        else:
            self.confidence = "low"
