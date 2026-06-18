import re
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from devguard.detection.scoring import DetectionResult, DetectionFlag
from devguard.detection.content import ContentDetector
from devguard.detection.profile import ProfileDetector
from devguard.detection.behavioral import BehavioralDetector
from devguard.detection.fingerprint import FingerprintDetector
from devguard.detection.ip_intel import IPIntelDetector

logger = logging.getLogger("devguard.detection.engine")

class DetectionEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Load weights and thresholds from config
        self.weights = self.config.get("weights", {
            "content": 0.25,
            "profile": 0.20,
            "behavioral": 0.20,
            "fingerprint": 0.20,
            "ip_intel": 0.15
        })
        self.thresholds = self.config.get("thresholds", {
            "suspicious": 0.4,
            "likely_bot": 0.7,
            "confirmed_bot": 0.9
        })

        # Instantiate detectors
        self.content_detector = ContentDetector(self.config)
        self.profile_detector = ProfileDetector(self.config)
        self.behavioral_detector = BehavioralDetector(self.config)
        self.fingerprint_detector = FingerprintDetector(self.config)
        self.ip_detector = IPIntelDetector(self.config.get("ip_intel"))

    async def scan_user(
        self,
        user_profile: Dict[str, Any],
        comments: List[Dict[str, Any]],
        fingerprint_data: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        custom_rules: Optional[List[Any]] = None  # List of Rule database objects
    ) -> DetectionResult:
        """Runs all detectors on a user and matches custom rules to calculate risk score."""
        username = user_profile.get("username", "")
        user_id = user_profile.get("id")
        
        logger.info(f"Scanning user: {username} (ID: {user_id})")
        
        result = DetectionResult(
            username=username,
            user_id=user_id
        )

        # 1. Profile Detector
        try:
            profile_flags = self.profile_detector.detect(user_profile)
            result.flags.extend(profile_flags)
        except Exception as e:
            logger.error(f"Error in profile detector for {username}: {e}", exc_info=True)

        # 2. Content & Behavioral Detector
        comment_bodies = []
        comment_timestamps = []
        
        for c in comments:
            body = c.get("body_html") or c.get("body") or ""
            comment_bodies.append(body)
            
            created_str = c.get("created_at")
            if created_str:
                try:
                    if isinstance(created_str, str):
                        clean_date = created_str.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_date)
                    else:
                        dt = created_str
                    comment_timestamps.append(dt)
                except Exception:
                    pass

        # Content scanning on each comment (combine history for fuzzy duplication check)
        history = []
        for body in comment_bodies:
            try:
                content_flags = self.content_detector.detect(body, history=history)
                result.flags.extend(content_flags)
                # Keep a window of history
                history.append(body)
                if len(history) > 15:
                    history.pop(0)
            except Exception as e:
                logger.error(f"Error in content detector for {username}: {e}")

        # Behavioral scanning
        try:
            behavior_flags = self.behavioral_detector.detect(comment_timestamps)
            result.flags.extend(behavior_flags)
        except Exception as e:
            logger.error(f"Error in behavioral detector for {username}: {e}")

        # 3. Fingerprint Detector
        if fingerprint_data:
            try:
                fp_flags = self.fingerprint_detector.detect(fingerprint_data)
                result.flags.extend(fp_flags)
            except Exception as e:
                logger.error(f"Error in fingerprint detector for {username}: {e}")

        # 4. IP Intelligence Detector
        # Resolve IP if not passed but available in fingerprint
        ip = ip_address or (fingerprint_data.get("ip_address") if fingerprint_data else None)
        if ip:
            try:
                ip_flags = await self.ip_detector.detect(ip)
                result.flags.extend(ip_flags)
            except Exception as e:
                logger.error(f"Error in IP intelligence detector for {username}: {e}")

        # 5. Apply Custom Database Rules (from Learn mode)
        if custom_rules:
            for rule in custom_rules:
                if not rule.is_active:
                    continue
                try:
                    if rule.pattern_type == "username_regex":
                        if re.search(rule.pattern, username, re.IGNORECASE):
                            result.flags.append(DetectionFlag(
                                detector="profile",
                                rule_name=f"custom_rule_{rule.name}",
                                severity=1.0,  # Custom rule hits are critical
                                description=f"Matched custom username pattern: {rule.description or rule.pattern}",
                                evidence={"username": username, "pattern": rule.pattern}
                            ))
                    elif rule.pattern_type == "content_regex":
                        for body in comment_bodies:
                            if re.search(rule.pattern, body, re.IGNORECASE):
                                result.flags.append(DetectionFlag(
                                    detector="content",
                                    rule_name=f"custom_rule_{rule.name}",
                                    severity=1.0,
                                    description=f"Comment matched custom content pattern: {rule.description or rule.pattern}",
                                    evidence={"comment_body": body[:150], "pattern": rule.pattern}
                                ))
                                break
                    elif rule.pattern_type == "ip_range" and ip:
                        # Simple substring match or CIDR
                        if rule.pattern in ip:
                            result.flags.append(DetectionFlag(
                                detector="ip_intel",
                                rule_name=f"custom_rule_{rule.name}",
                                severity=1.0,
                                description=f"IP matches blocked range: {rule.pattern}",
                                evidence={"ip": ip, "pattern": rule.pattern}
                            ))
                except Exception as e:
                    logger.error(f"Error applying custom rule {rule.name}: {e}")

        # Calculate final verdict
        result.compute_composite_verdict(self.weights, self.thresholds)
        logger.info(f"Scan complete. Username: {username}, Score: {result.risk_score:.2f}, Verdict: {result.verdict}")
        return result
