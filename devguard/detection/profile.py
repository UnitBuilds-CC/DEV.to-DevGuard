import re
import logging
import unicodedata
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from devguard.detection.scoring import DetectionFlag

logger = logging.getLogger("devguard.detection.profile")

# Simple helper to classify script types of characters
def get_char_script(char: str) -> Optional[str]:
    try:
        name = unicodedata.name(char)
        first_word = name.split()[0]
        if first_word in ("LATIN", "CYRILLIC", "GREEK", "HEBREW", "ARABIC", "HANGUL", "KATAKANA", "HIRAGANA", "CJK"):
            return first_word
        return "OTHER"
    except ValueError:
        return None

def detect_mixed_scripts(text: str) -> bool:
    """Detects if a string contains characters from mixed scripts (e.g. Latin + Cyrillic lookalikes)."""
    scripts = set()
    for char in text:
        if char.isalnum():
            script = get_char_script(char)
            if script and script != "OTHER":
                scripts.add(script)
    # If more than one major script is mixed (e.g. LATIN and CYRILLIC)
    return len(scripts) > 1

class ProfileDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def detect(self, user_profile: Dict[str, Any]) -> List[DetectionFlag]:
        """Analyzes a Forem user profile dictionary and returns detection flags."""
        flags = []
        
        username = user_profile.get("username", "")
        name = user_profile.get("name", "")
        created_at_str = user_profile.get("created_at") or user_profile.get("joined_at")
        followers_count = int(user_profile.get("followers_count") or 0)
        following_count = int(user_profile.get("following_count") or 0)
        post_count = int(user_profile.get("post_count") or user_profile.get("articles_count") or 0)
        comment_count = int(user_profile.get("comment_count") or 0)
        bio = user_profile.get("summary") or user_profile.get("bio") or ""
        profile_image = user_profile.get("profile_image") or user_profile.get("profile_image_url") or ""

        # 1. Homoglyph / Mixed script spoofing check
        if username and detect_mixed_scripts(username):
            flags.append(DetectionFlag(
                detector="profile",
                rule_name="mixed_script_username",
                severity=0.85,
                description="Username contains characters from multiple Unicode scripts (homoglyph risk)",
                evidence={"username": username}
            ))
            
        if name and detect_mixed_scripts(name):
            flags.append(DetectionFlag(
                detector="profile",
                rule_name="mixed_script_name",
                severity=0.7,
                description="Display name contains characters from multiple Unicode scripts",
                evidence={"name": name}
            ))

        # 2. Account Age & Activity
        account_age_days = 365.0
        if created_at_str:
            try:
                # Expect formats like "2026-06-18T18:01:41Z" or datetime objects
                if isinstance(created_at_str, str):
                    # Strip Z and parse
                    clean_date = created_at_str.replace("Z", "+00:00")
                    created_at = datetime.fromisoformat(clean_date)
                else:
                    created_at = created_at_str
                
                # Make timezone aware
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                    
                now = datetime.now(timezone.utc)
                account_age_days = max(0.1, (now - created_at).total_seconds() / 86400.0)
            except Exception as e:
                logger.error(f"Error parsing created_at timestamp: {e}")

        # Flag extremely new account
        if account_age_days < 1.0:
            flags.append(DetectionFlag(
                detector="profile",
                rule_name="new_account",
                severity=0.5,
                description=f"Account is less than 24 hours old ({account_age_days:.1f} hours)",
                evidence={"age_days": account_age_days}
            ))
            
            # New account + high activity
            if comment_count > 10 or post_count > 5:
                flags.append(DetectionFlag(
                    detector="profile",
                    rule_name="high_activity_new_account",
                    severity=0.85,
                    description=f"Brand new account with high activity: {comment_count} comments, {post_count} posts",
                    evidence={"age_days": account_age_days, "comments": comment_count, "posts": post_count}
                ))

        # 3. Follower / Following Ratio
        # Bots typically follow many people to get follow-backs, but have very few followers themselves
        if following_count > 100 and followers_count == 0:
            flags.append(DetectionFlag(
                detector="profile",
                rule_name="one_sided_following",
                severity=0.75,
                description=f"Following {following_count} users but has 0 followers",
                evidence={"followers": followers_count, "following": following_count}
            ))
        elif following_count > 500 and (followers_count / following_count) < 0.02:
            ratio = followers_count / following_count
            flags.append(DetectionFlag(
                detector="profile",
                rule_name="suspicious_follow_ratio",
                severity=0.6,
                description=f"Following {following_count} users but only has {followers_count} followers (ratio: {ratio:.1%})",
                evidence={"followers": followers_count, "following": following_count, "ratio": ratio}
            ))

        # 4. Profile completeness
        # Defaults, empty bio
        is_incomplete = False
        completeness_evidence = {}
        if not bio or len(bio.strip()) < 5:
            completeness_evidence["no_bio"] = True
            is_incomplete = True
        
        # Check default profile image patterns (Forem default avatars usually point to generic urls)
        if not profile_image or "default" in profile_image or "gravatar.com/avatar" in profile_image:
            completeness_evidence["default_avatar"] = True
            is_incomplete = True
            
        if is_incomplete and account_age_days < 7.0:
            # Incomplete profile on relatively new account
            severity = 0.4 if len(completeness_evidence) == 1 else 0.55
            flags.append(DetectionFlag(
                detector="profile",
                rule_name="incomplete_profile",
                severity=severity,
                description="Profile is incomplete (no bio and/or default avatar) on a young account",
                evidence=completeness_evidence
            ))

        # 5. Username patterns
        # Username ends with long random digits (e.g. bot94827184)
        if username:
            digit_suffix_match = re.search(r'([a-zA-Z_]+)(\d{6,})$', username)
            if digit_suffix_match:
                flags.append(DetectionFlag(
                    detector="profile",
                    rule_name="numeric_suffix_username",
                    severity=0.5,
                    description="Username ends with a long sequence of numbers (indicative of automated generator)",
                    evidence={"suffix": digit_suffix_match.group(2)}
                ))
            
            # Entirely random looking username (high consonant-to-vowel ratio, or no vowels)
            clean_username = re.sub(r'[^a-zA-Z]', '', username).lower()
            if len(clean_username) >= 8:
                vowels = sum(1 for c in clean_username if c in 'aeiou')
                vowel_ratio = vowels / len(clean_username)
                if vowel_ratio < 0.15:
                    flags.append(DetectionFlag(
                        detector="profile",
                        rule_name="gibberish_username",
                        severity=0.6,
                        description=f"Username has a suspiciously low ratio of vowels ({vowel_ratio:.1%})",
                        evidence={"vowels": vowels, "len": len(clean_username), "ratio": vowel_ratio}
                    ))

        return flags
