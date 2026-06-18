import pytest
from datetime import datetime, timedelta
from devguard.detection.content import ContentDetector
from devguard.detection.profile import ProfileDetector, detect_mixed_scripts
from devguard.detection.behavioral import BehavioralDetector
from devguard.detection.fingerprint import FingerprintDetector
from devguard.detection.scoring import DetectionResult

def test_mixed_scripts_detector():
    # True for mixed Latin and Cyrillic (e.g. Cyrillic 'a' is U+0430, Latin 'a' is U+0061)
    # Let's test a simple mixture
    assert detect_mixed_scripts("johnа") is True  # Cyrillic 'а' at the end
    assert detect_mixed_scripts("john") is False   # Pure latin
    assert detect_mixed_scripts("1234") is False   # Numeric

def test_content_detector():
    detector = ContentDetector()
    
    # Test spam keyword
    flags = detector.detect("Click here for free money and crypto investments on telegram!")
    rule_names = [f.rule_name for f in flags]
    assert "spam_keywords" in rule_names
    
    # Test shortener domains
    flags = detector.detect("Check my site: https://bit.ly/3asdf")
    rule_names = [f.rule_name for f in flags]
    assert "spam_url_shortener" in rule_names

    # Test fuzzy duplicate comment
    history = [
        "This is a very cool post, thanks for sharing!",
        "Another comment that is quite different"
    ]
    flags = detector.detect("This is a very cool post, thanks for sharing!", history=history)
    rule_names = [f.rule_name for f in flags]
    assert "duplicate_comment" in rule_names

def test_profile_detector():
    detector = ProfileDetector()
    
    # Young profile with high activity
    young_profile = {
        "username": "bot_user_998123",
        "name": "Normal Name",
        "created_at": (datetime.now() - timedelta(hours=3)).isoformat() + "Z",
        "followers_count": 5,
        "following_count": 600,
        "comment_count": 25,
        "post_count": 10,
        "summary": ""
    }
    
    flags = detector.detect(young_profile)
    rule_names = [f.rule_name for f in flags]
    assert "new_account" in rule_names
    assert "high_activity_new_account" in rule_names
    assert "suspicious_follow_ratio" in rule_names
    assert "numeric_suffix_username" in rule_names

def test_behavioral_detector():
    detector = BehavioralDetector()
    
    # Test sub 3s speed limits
    now = datetime.now()
    fast_timestamps = [now, now + timedelta(seconds=1), now + timedelta(seconds=2)]
    flags = detector.detect(fast_timestamps)
    rule_names = [f.rule_name for f in flags]
    assert "burst_posting" in rule_names

    # Test robotic cadence (exactly 60s intervals)
    cadence_timestamps = [now + timedelta(seconds=60 * i) for i in range(5)]
    flags = detector.detect(cadence_timestamps)
    rule_names = [f.rule_name for f in flags]
    assert "robotic_cadence" in rule_names

def test_fingerprint_detector():
    detector = FingerprintDetector()
    
    fp_payload = {
        "webdriver": True,
        "cdp_artifacts": True,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "plugins_len": 0,
        "platform": "Linux x86_64",
        "permission_state": "prompt",
        "notification_permission": "denied"
    }
    
    flags = detector.detect(fp_payload)
    rule_names = [f.rule_name for f in flags]
    assert "webdriver_flag" in rule_names
    assert "cdp_artifacts_present" in rule_names
    assert "headless_no_plugins" in rule_names
    assert "ua_platform_mismatch" in rule_names
    assert "permission_anomaly" in rule_names

def test_telemetry_detection():
    detector = FingerprintDetector()
    
    # 1. Robotic mouse movements (many moves, constant speed, straight lines)
    bot_mouse_fp = {
        "telemetry": {
            "mouse_moves": 10,
            "mouse_robotic_lines": 8,
            "mouse_speed_variance": 0.0,
            "key_presses": 0,
            "key_dwell_variance": 0.0,
            "key_paste_count": 0,
            "scroll_events": 0
        }
    }
    
    flags = detector.detect(bot_mouse_fp)
    rule_names = [f.rule_name for f in flags]
    assert "robotic_mouse_path" in rule_names
    assert "constant_mouse_speed" in rule_names
    assert "no_interaction_telemetry" not in rule_names

    # 2. Robotic keyboard dwell time (uniform dwell time)
    bot_keys_fp = {
        "telemetry": {
            "mouse_moves": 0,
            "mouse_robotic_lines": 0,
            "mouse_speed_variance": 0.0,
            "key_presses": 10,
            "key_dwell_variance": 0.05,
            "key_paste_count": 0,
            "scroll_events": 0
        }
    }
    flags = detector.detect(bot_keys_fp)
    rule_names = [f.rule_name for f in flags]
    assert "constant_keyboard_dwell" in rule_names

    # 3. Paste injection
    paste_fp = {
        "telemetry": {
            "mouse_moves": 0,
            "mouse_robotic_lines": 0,
            "mouse_speed_variance": 0.0,
            "key_presses": 0,
            "key_dwell_variance": 0.0,
            "key_paste_count": 1,
            "scroll_events": 0
        }
    }
    flags = detector.detect(paste_fp)
    rule_names = [f.rule_name for f in flags]
    assert "paste_injection" in rule_names

