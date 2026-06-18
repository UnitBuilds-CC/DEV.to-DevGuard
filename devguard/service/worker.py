import asyncio
import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from devguard.database import SessionLocal, Scan, Rule
from devguard.detection.engine import DetectionEngine
from devguard.modes.detect import process_detection_result
from devguard.modes.execute import ExecutionController
from devguard.api import ForemClient, UsersAPI, CommentsAPI

logger = logging.getLogger("devguard.service.worker")

class DevGuardWorker:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.engine = DetectionEngine(config)
        self.executor = ExecutionController(config)

    async def scan_single_user_now(self, username: str) -> Dict[str, Any]:
        """Manually trigger a scan for a single user and return the results."""
        logger.info(f"Worker manual scan requested for: {username}")
        db = SessionLocal()
        
        api_config = self.config.get("api", {})
        client = ForemClient(
            base_url=api_config.get("base_url", "https://dev.to/api"),
            api_key=api_config.get("api_key", ""),
            rate_limit_per_sec=api_config.get("rate_limit", 10)
        )
        users_api = UsersAPI(client)
        
        try:
            profile = await users_api.get_user_profile_by_username(username)
            if not profile:
                return {"error": f"User '{username}' not found on platform"}

            custom_rules = db.query(Rule).filter(Rule.is_active == True).all()
            
            result = await self.engine.scan_user(
                user_profile=profile,
                comments=[],
                custom_rules=custom_rules
            )
            
            user_record = process_detection_result(db, None, result, profile)
            
            # If execute mode is on, run enforcement
            action_taken = await self.executor.evaluate_and_enforce(db, users_api, user_record, result.risk_score)
            
            return {
                "username": username,
                "risk_score": result.risk_score,
                "verdict": result.verdict,
                "flags": [f.model_dump() for f in result.flags],
                "action_taken": action_taken.action_type if action_taken else None
            }
        except Exception as e:
            logger.error(f"Worker failed to scan {username}: {e}", exc_info=True)
            return {"error": str(e)}
        finally:
            await client.close()
            db.close()
