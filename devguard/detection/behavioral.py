import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from devguard.detection.scoring import DetectionFlag

logger = logging.getLogger("devguard.detection.behavioral")

class BehavioralDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def detect(self, comment_timestamps: List[datetime]) -> List[DetectionFlag]:
        """Analyzes a list of comment timestamps for robotic patterns or speed violations."""
        flags = []
        if not comment_timestamps or len(comment_timestamps) < 2:
            return flags

        # Sort chronologically
        sorted_times = sorted(comment_timestamps)
        
        # Calculate deltas in seconds
        deltas = []
        for i in range(len(sorted_times) - 1):
            delta = (sorted_times[i+1] - sorted_times[i]).total_seconds()
            deltas.append(delta)

        # 1. Direct speed check (burst posting)
        sub_three_sec_count = sum(1 for d in deltas if d < 3.0)
        if sub_three_sec_count > 0:
            severity = 0.6 if sub_three_sec_count == 1 else 0.9
            flags.append(DetectionFlag(
                detector="behavioral",
                rule_name="burst_posting",
                severity=severity,
                description=f"User posted comments faster than humanly possible (intervals < 3s, occurred {sub_three_sec_count} times)",
                evidence={"deltas": deltas, "sub_3s_count": sub_three_sec_count}
            ))

        # 2. Robotic cadence / Regular intervals
        # If we have at least 4 comments, we can check for suspiciously uniform intervals (low std deviation)
        if len(deltas) >= 3:
            mean_delta = sum(deltas) / len(deltas)
            
            # If they are posting relatively fast (e.g. mean interval less than 15 minutes)
            if mean_delta < 900.0:
                variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                std_dev = variance ** 0.5
                
                # Coeff of variation (std_dev / mean) - if very close to 0, intervals are perfectly identical
                cv = std_dev / mean_delta if mean_delta > 0 else 1.0
                
                # If CV is less than 0.05 (5% variation), it's highly likely to be automated
                if cv < 0.05:
                    flags.append(DetectionFlag(
                        detector="behavioral",
                        rule_name="robotic_cadence",
                        severity=0.85,
                        description=f"User comments follow a robotic timing cadence (average interval of {mean_delta:.1f}s with only {cv:.1%} variance)",
                        evidence={"mean_interval": mean_delta, "variance_coefficient": cv, "deltas": deltas}
                    ))
                elif cv < 0.12:
                    flags.append(DetectionFlag(
                        detector="behavioral",
                        rule_name="highly_regular_intervals",
                        severity=0.65,
                        description=f"User comments show highly regular time intervals (average interval of {mean_delta:.1f}s, variance: {cv:.1%})",
                        evidence={"mean_interval": mean_delta, "variance_coefficient": cv, "deltas": deltas}
                    ))

        return flags
