import logging
from typing import List, Dict, Any, Optional
from devguard.detection.scoring import DetectionFlag

logger = logging.getLogger("devguard.detection.fingerprint")

class FingerprintDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def detect(self, fp_data: Dict[str, Any]) -> List[DetectionFlag]:
        """Analyzes browser fingerprint data collected by client-side JS payload."""
        flags = []
        if not fp_data:
            return flags

        # 1. WebDriver Flag
        if fp_data.get("webdriver") is True:
            flags.append(DetectionFlag(
                detector="fingerprint",
                rule_name="webdriver_flag",
                severity=0.95,
                description="Browser explicitly reports navigator.webdriver = true",
                evidence={"webdriver": True}
            ))

        # 2. CDP/Automation Globals
        if fp_data.get("cdp_artifacts") is True:
            flags.append(DetectionFlag(
                detector="fingerprint",
                rule_name="cdp_artifacts_present",
                severity=0.95,
                description="CDP or Selenium automation window properties/variables detected",
                evidence={"cdp_artifacts": True}
            ))

        # 3. Headless Browser Signatures
        # Headless Chrome typically reports navigator.plugins.length = 0
        user_agent = fp_data.get("user_agent", "")
        plugins_len = fp_data.get("plugins_len", 0)
        
        # Check if Chrome but plugins list is empty (almost all normal Chrome installations have default plugins)
        if "Chrome" in user_agent and "Mobile" not in user_agent and plugins_len == 0:
            flags.append(DetectionFlag(
                detector="fingerprint",
                rule_name="headless_no_plugins",
                severity=0.8,
                description="Headless browser signature detected (Chrome with 0 plugins)",
                evidence={"user_agent": user_agent, "plugins_len": plugins_len}
            ))

        # 4. User-Agent vs Platform Inconsistency
        platform = fp_data.get("platform", "")
        if platform:
            ua_lower = user_agent.lower()
            plat_lower = platform.lower()
            
            mismatch = False
            if "win" in ua_lower and "win" not in plat_lower:
                mismatch = True
            elif "mac" in ua_lower and "mac" not in plat_lower:
                mismatch = True
            elif "linux" in ua_lower and "linux" not in plat_lower:
                mismatch = True
                
            if mismatch:
                flags.append(DetectionFlag(
                    detector="fingerprint",
                    rule_name="ua_platform_mismatch",
                    severity=0.75,
                    description=f"User-Agent indicates OS '{user_agent}' but platform reports '{platform}'",
                    evidence={"user_agent": user_agent, "platform": platform}
                ))

        # 5. Permission API anomalies (Headless Chrome often has permission inconsistencies)
        # Notifications state is "denied" but querying notifications permission gives "prompt"
        permission_state = fp_data.get("permission_state", "")
        notification_permission = fp_data.get("notification_permission", "")
        if permission_state == "prompt" and notification_permission == "denied":
            flags.append(DetectionFlag(
                detector="fingerprint",
                rule_name="permission_anomaly",
                severity=0.8,
                description="Inconsistent Browser Permission state (Notification API spoofing)",
                evidence={
                    "permission_state": permission_state,
                    "notification_permission": notification_permission
                }
            ))

        # 6. Active Telemetry checks (Mouse / Keyboard / Scroll)
        telemetry = fp_data.get("telemetry")
        if telemetry:
            mouse_moves = int(telemetry.get("mouse_moves", 0))
            mouse_robotic_lines = int(telemetry.get("mouse_robotic_lines", 0))
            mouse_speed_var = float(telemetry.get("mouse_speed_variance", 0.0))
            
            key_presses = int(telemetry.get("key_presses", 0))
            key_dwell_var = float(telemetry.get("key_dwell_variance", 0.0))
            key_paste_count = int(telemetry.get("key_paste_count", 0))
            
            scroll_events = int(telemetry.get("scroll_events", 0))

            # Robotic mouse paths (straight-line trajectories)
            if mouse_moves >= 8 and mouse_robotic_lines > 0:
                robotic_ratio = mouse_robotic_lines / mouse_moves
                if robotic_ratio > 0.65:
                    flags.append(DetectionFlag(
                        detector="fingerprint",
                        rule_name="robotic_mouse_path",
                        severity=0.85,
                        description=f"Mouse movement exhibits linear path segments (Ratio: {robotic_ratio:.1%})",
                        evidence={"mouse_moves": mouse_moves, "robotic_lines": mouse_robotic_lines, "ratio": robotic_ratio}
                    ))
            
            # Constant mouse velocity
            if mouse_moves >= 8 and mouse_speed_var < 0.0001:
                flags.append(DetectionFlag(
                    detector="fingerprint",
                    rule_name="constant_mouse_speed",
                    severity=0.8,
                    description="Mouse cursor speed has zero variance (indicates automation script)",
                    evidence={"mouse_moves": mouse_moves, "speed_variance": mouse_speed_var}
                ))

            # Constant keyboard dwell time (robotic keypress cadence)
            if key_presses >= 5 and key_dwell_var < 0.1:
                flags.append(DetectionFlag(
                    detector="fingerprint",
                    rule_name="constant_keyboard_dwell",
                    severity=0.85,
                    description="Keystroke press duration has zero variance (indicates automated key injection)",
                    evidence={"key_presses": key_presses, "dwell_variance": key_dwell_var}
                ))

            # Paste injection with zero keypresses
            if key_paste_count > 0 and key_presses == 0:
                flags.append(DetectionFlag(
                    detector="fingerprint",
                    rule_name="paste_injection",
                    severity=0.45,
                    description="Content entered via paste event without any natural keyboard presses",
                    evidence={"paste_count": key_paste_count, "key_presses": key_presses}
                ))

            # Bypassed interaction (Headless form submit without telemetry events)
            if mouse_moves == 0 and key_presses == 0 and scroll_events == 0:
                flags.append(DetectionFlag(
                    detector="fingerprint",
                    rule_name="no_interaction_telemetry",
                    severity=0.6,
                    description="Session contains zero mouse, scroll, or keyboard interactions (indicates headless scripts)",
                    evidence={"mouse_moves": 0, "key_presses": 0, "scroll_events": 0}
                ))

        return flags
