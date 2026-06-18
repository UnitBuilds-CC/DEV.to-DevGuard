import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from devguard.database import User, Flag, Scan
from devguard.detection.scoring import DetectionResult

logger = logging.getLogger("devguard.modes.detect")

def process_detection_result(
    db: Session,
    scan_id: Optional[int],
    result: DetectionResult,
    user_data: Dict[str, Any]
) -> User:
    """Saves or updates a user profile with the scan results and logs individual detection flags."""
    # Try to find existing cached user
    user = db.query(User).filter(User.id == result.user_id).first()
    
    if not user:
        user = User(
            id=result.user_id,
            username=result.username,
            name=user_data.get("name"),
            joined_at=datetime.utcnow(),
            comment_count=int(user_data.get("comment_count") or 0),
            post_count=int(user_data.get("post_count") or user_data.get("articles_count") or 0),
            followers_count=int(user_data.get("followers_count") or 0),
            following_count=int(user_data.get("following_count") or 0),
        )
        db.add(user)
        db.flush()  # Populates user.id if it's generated, but for Forem it's provided

    # Check if user is whitelisted
    if user.is_whitelisted:
        logger.info(f"User {user.username} is whitelisted, skipping score updates.")
        return user

    # Update detection stats
    user.risk_score = result.risk_score
    user.verdict = result.verdict
    user.last_scanned_at = datetime.utcnow()
    
    # Save new flags
    # We clear old flags associated with the user first, or just insert new ones linked to this scan
    for flag in result.flags:
        db_flag = Flag(
            user_id=user.id,
            scan_id=scan_id,
            detector=flag.detector,
            rule_name=flag.rule_name,
            severity=flag.severity,
            description=flag.description,
        )
        db_flag.evidence = flag.evidence
        db.add(db_flag)

    db.commit()
    return user
