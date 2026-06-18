import pytest
from unittest.mock import AsyncMock
from devguard.database import User, WhitelistEntry, Rule, Flag, Action, Report
from devguard.modes.detect import process_detection_result
from devguard.modes.execute import ExecutionController
from devguard.modes.learn import LearnModeController
from devguard.detection.scoring import DetectionResult, DetectionFlag

def test_detect_mode_saves_user_and_flags(db_session):
    result = DetectionResult(
        username="spambot12",
        user_id=88319,
        risk_score=0.95,
        verdict="confirmed_bot",
        flags=[
            DetectionFlag(
                detector="content",
                rule_name="spam_keywords",
                severity=0.8,
                description="Triggered keywords"
            )
        ]
    )
    user_data = {"name": "Bot Twelve", "comment_count": 50, "followers_count": 0}
    
    # Process
    user = process_detection_result(db_session, scan_id=1, result=result, user_data=user_data)
    
    # Verify in DB
    db_user = db_session.query(User).filter(User.id == 88319).first()
    assert db_user is not None
    assert db_user.username == "spambot12"
    assert db_user.risk_score == 0.95
    assert db_user.verdict == "confirmed_bot"
    
    db_flags = db_session.query(Flag).filter(Flag.user_id == 88319).all()
    assert len(db_flags) == 1
    assert db_flags[0].rule_name == "spam_keywords"
    assert db_flags[0].scan_id == 1

@pytest.mark.asyncio
async def test_execute_mode_respects_whitelist(db_session):
    # Setup whitelisted user
    user = User(id=777, username="good_user", verdict="confirmed_bot", risk_score=0.98, is_whitelisted=True)
    db_session.add(user)
    db_session.commit()
    
    mock_users_api = AsyncMock()
    
    config = {
        "execute": {"enabled": True, "dry_run": False, "max_actions_per_hour": 10},
        "thresholds": {"confirmed_bot": 0.9}
    }
    controller = ExecutionController(config)
    
    action = await controller.evaluate_and_enforce(db_session, mock_users_api, user, 0.98)
    
    # Assert no actions taken
    assert action is None
    mock_users_api.suspend_user.assert_not_called()

@pytest.mark.asyncio
async def test_execute_mode_dry_run(db_session):
    user = User(id=888, username="bad_user", verdict="confirmed_bot", risk_score=0.98, is_whitelisted=False)
    db_session.add(user)
    db_session.commit()
    
    mock_users_api = AsyncMock()
    
    config = {
        "execute": {"enabled": True, "dry_run": True, "max_actions_per_hour": 10},
        "thresholds": {"confirmed_bot": 0.9}
    }
    controller = ExecutionController(config)
    
    action = await controller.evaluate_and_enforce(db_session, mock_users_api, user, 0.98)
    
    assert action is not None
    assert action.action_type == "dry_run_suspend"
    assert action.status == "success"
    mock_users_api.suspend_user.assert_not_called()

def test_learn_mode_preview_and_commit(db_session):
    # Ingest mock users
    u1 = User(id=1, username="crypto_scammer", verdict="suspicious")
    u2 = User(id=2, username="legit_creator", verdict="clean", is_whitelisted=True)
    db_session.add_all([u1, u2])
    db_session.commit()
    
    controller = LearnModeController()
    
    # Test username preview
    preview = controller.preview_rule_impact(db_session, "username_regex", "crypto_.*")
    assert preview["total_matches"] == 1
    assert "crypto_scammer" in preview["matched_usernames"]
    assert preview["whitelist_hits_count"] == 0

    # Commit rule
    rule = controller.commit_rule(
        db=db_session,
        name="crypto_username_block",
        pattern_type="username_regex",
        pattern="crypto_.*",
        description="Blocks crypto username patterns"
    )
    
    db_rule = db_session.query(Rule).filter(Rule.name == "crypto_username_block").first()
    assert db_rule is not None
    assert db_rule.pattern == "crypto_.*"
