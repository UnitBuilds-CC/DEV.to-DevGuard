import re
import logging
from typing import List, Dict, Any, Optional
from rapidfuzz import fuzz
from devguard.detection.scoring import DetectionFlag

logger = logging.getLogger("devguard.detection.content")

# Common spam patterns and keywords
SPAM_KEYWORDS = [
    r"\btelegram\b", r"\bwhatsapp\b", r"\bcrypto\b", r"\bwhatsapp\b",
    r"\bclick here\b", r"\bfree money\b", r"\bpassive income\b",
    r"\binvestment opportunity\b", r"\bwhatsapp me\b", r"\btelegram group\b",
    r"\binbox me\b", r"\bdm me\b", r"\bget rich\b", r"\bguaranteed profit\b",
    r"\bgiveaway\b", r"\bcheck my profile\b", r"\bvisit my site\b",
    r"\bpromotional offer\b"
]

# URL shorteners and known spam domains
SPAM_DOMAINS = [
    r"bit\.ly", r"tinyurl\.com", r"t\.co", r"cutt\.ly", r"rebrand\.ly",
    r"shorturl\.at", r"dub\.co", r"linktr\.ee", r"t\.me", r"wa\.me"
]

class ContentDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        # Compile patterns
        self.keyword_patterns = [re.compile(p, re.IGNORECASE) for p in SPAM_KEYWORDS]
        self.domain_patterns = [re.compile(d, re.IGNORECASE) for d in SPAM_DOMAINS]

    def detect(self, comment_body: str, history: List[str] = None) -> List[DetectionFlag]:
        """Analyzes a comment body and returns detection flags."""
        flags = []
        body = comment_body.strip()
        if not body:
            return flags

        # 1. URL Analysis
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        if urls:
            spam_domain_matches = []
            for url in urls:
                for pat in self.domain_patterns:
                    if pat.search(url):
                        spam_domain_matches.append(url)
            
            if spam_domain_matches:
                flags.append(DetectionFlag(
                    detector="content",
                    rule_name="spam_url_shortener",
                    severity=0.8,
                    description=f"Comment contains suspicious or shortener URLs: {', '.join(spam_domain_matches)}",
                    evidence={"urls": spam_domain_matches}
                ))
            elif len(urls) >= 3:
                flags.append(DetectionFlag(
                    detector="content",
                    rule_name="excessive_urls",
                    severity=0.6,
                    description=f"Comment contains an unusually high number of links ({len(urls)})",
                    evidence={"url_count": len(urls), "urls": urls}
                ))

        # 2. Keyword/Template matching
        matched_keywords = []
        for pat in self.keyword_patterns:
            matches = pat.findall(body)
            if matches:
                matched_keywords.extend(matches)
                
        if matched_keywords:
            severity = 0.5 if len(matched_keywords) == 1 else 0.8
            flags.append(DetectionFlag(
                detector="content",
                rule_name="spam_keywords",
                severity=severity,
                description=f"Comment contains spam keywords: {', '.join(set(matched_keywords))}",
                evidence={"keywords": list(set(matched_keywords))}
            ))

        # 3. Gibberish / Character anomalies
        # High ratio of non-alphanumeric or repeated chars
        if len(body) > 10:
            # Check repeated letters (e.g., "aaaaa" or "helloooooo")
            repeated_char_match = re.search(r'(.)\1{4,}', body)
            if repeated_char_match:
                flags.append(DetectionFlag(
                    detector="content",
                    rule_name="repeated_characters",
                    severity=0.4,
                    description=f"Comment contains excessively repeated characters: '{repeated_char_match.group(0)}'",
                    evidence={"sequence": repeated_char_match.group(0)}
                ))
            
            # Check upper case ratio
            alpha_chars = [c for c in body if c.isalpha()]
            if alpha_chars:
                upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
                if upper_ratio > 0.8 and len(alpha_chars) > 8:
                    flags.append(DetectionFlag(
                        detector="content",
                        rule_name="excessive_caps",
                        severity=0.4,
                        description="Comment is written in almost all caps",
                        evidence={"caps_ratio": upper_ratio}
                    ))

        # 4. History/Duplication Check (Fuzzy match)
        if history:
            max_sim = 0.0
            most_similar = ""
            for old_comment in history:
                sim = fuzz.ratio(body, old_comment) / 100.0
                if sim > max_sim:
                    max_sim = sim
                    most_similar = old_comment
            
            if max_sim > 0.85:
                flags.append(DetectionFlag(
                    detector="content",
                    rule_name="duplicate_comment",
                    severity=0.75 if max_sim > 0.95 else 0.6,
                    description=f"Comment is extremely similar ({max_sim:.1%}) to a previous comment",
                    evidence={"similarity": max_sim, "previous_match": most_similar[:100]}
                ))

        return flags
