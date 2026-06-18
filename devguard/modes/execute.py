import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from devguard.database import User, Action, WhitelistEntry
from devguard.api.users import UsersAPI

logger = logging.getLogger("devguard.modes.execute")

class ExecutionController:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.execute_config = self.config.get("execute", {})
        self.enabled = self.execute_config.get("enabled", False)
        self.dry_run = self.execute_config.get("dry_run", True)
        self.max_actions_per_hour = self.execute_config.get("max_actions_per_hour", 10)
        self.suspend_threshold = self.config.get("thresholds", {}).get("confirmed_bot", 0.9)

    async def evaluate_and_enforce(
        self,
        db: Session,
        users_api: UsersAPI,
        user: User,
        risk_score: float
    ) -> Optional[Action]:
        """Evaluates whether to suspend or block a user and executes if authorized."""
        if not self.enabled:
            logger.debug(f"Execution mode disabled. Skipping enforcement for {user.username}.")
            return None

        # 1. Whitelist Check
        # Check both User.is_whitelisted and WhitelistEntry table
        whitelist_entry = db.query(WhitelistEntry).filter(WhitelistEntry.username == user.username).first()
        if user.is_whitelisted or whitelist_entry:
            logger.info(f"User {user.username} is whitelisted. Enforcement skipped.")
            return None

        # 2. Threshold Check
        if risk_score < self.suspend_threshold:
            logger.debug(f"User {user.username} risk score {risk_score:.2f} below suspension threshold {self.suspend_threshold:.2f}.")
            return None

        # 3. Hourly Rate Limit Check
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_actions = db.query(Action).filter(
            Action.performed_at >= one_hour_ago,
            Action.status == "success",
            Action.action_type.in_(["suspend", "unpublish"])
        ).count()

        if recent_actions >= self.max_actions_per_hour:
            logger.warning(
                f"Rate limit exceeded: {recent_actions} actions taken in the last hour (max: {self.max_actions_per_hour}). "
                f"Enforcement for {user.username} is skipped."
            )
            # Log as dry-run or failed action
            action = Action(
                user_id=user.id,
                action_type="suspend",
                status="failed",
                details=f"Rate limit of {self.max_actions_per_hour} actions/hr exceeded. Block throttled."
            )
            db.add(action)
            db.commit()
            return action

        # 4. Dry Run vs Actual Execution
        action_type = "suspend"
        status = "pending"
        details = ""

        if self.dry_run:
            action_type = "dry_run_suspend"
            status = "success"
            details = f"[DRY RUN] Would suspend user {user.username} (Risk Score: {risk_score:.2f})"
            logger.info(details)
            
            action = Action(
                user_id=user.id,
                action_type=action_type,
                status=status,
                details=details
            )
            db.add(action)
            db.commit()
            return action
        else:
            logger.warning(f"AUTO-BLOCK: Suspending user {user.username} (Risk Score: {risk_score:.2f})")
            success = await users_api.suspend_user(user.id)
            
            if success:
                # Also unpublish content as standard practice for bots
                await users_api.unpublish_user_content(user.id)
                status = "success"
                details = f"Successfully suspended user and unpublished content. Risk Score: {risk_score:.2f}"
                logger.info(details)
            else:
                status = "failed"
                details = f"Failed to suspend user via Forem API. Check credentials/permissions."
                logger.error(details)

            action = Action(
                user_id=user.id,
                action_type=action_type,
                status=status,
                details=details
            )
            db.add(action)
            
            # Update user verdict to indicate suspended
            if success:
                user.verdict = "suspended"
                
            db.commit()
            return action
