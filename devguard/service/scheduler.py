import logging
from datetime import datetime
from typing import Dict, Any, Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session

from devguard.database import SessionLocal, Scan, Rule
from devguard.api import ForemClient, ArticlesAPI, CommentsAPI, UsersAPI, FollowersAPI
from devguard.detection.engine import DetectionEngine
from devguard.modes.detect import process_detection_result
from devguard.modes.execute import ExecutionController

logger = logging.getLogger("devguard.service.scheduler")

class DevGuardScheduler:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scheduler = AsyncIOScheduler()
        
        # Instantiate API clients
        api_config = config.get("api", {})
        self.client = ForemClient(
            base_url=api_config.get("base_url", "https://dev.to/api"),
            api_key=api_config.get("api_key", ""),
            rate_limit_per_sec=api_config.get("rate_limit", 10)
        )
        self.articles_api = ArticlesAPI(self.client)
        self.comments_api = CommentsAPI(self.client)
        self.users_api = UsersAPI(self.client)
        self.followers_api = FollowersAPI(self.client)
        
        # Detection engine and operational controllers
        self.engine = DetectionEngine(config)
        self.executor = ExecutionController(config)
        
        # Last scanned comment code/id cache (to avoid duplicate processing)
        self.scanned_comment_ids = set()

    def start(self):
        """Starts the scheduler jobs based on config settings."""
        service_config = self.config.get("service", {})
        if not service_config.get("enabled", True):
            logger.info("DevGuard background service is disabled in config.")
            return

        comment_interval = service_config.get("comment_scan_interval", 300)
        follower_interval = service_config.get("follower_scan_interval", 900)

        # Add recurring jobs
        self.scheduler.add_job(
            self.scan_recent_comments,
            "interval",
            seconds=comment_interval,
            id="comment_scan",
            replace_existing=True
        )
        self.scheduler.add_job(
            self.scan_new_followers,
            "interval",
            seconds=follower_interval,
            id="follower_scan",
            replace_existing=True
        )
        
        self.scheduler.start()
        logger.info(f"DevGuard scheduler started. Comment scan: {comment_interval}s, Follower scan: {follower_interval}s")

    def stop(self):
        """Stops the scheduler and closes the HTTP client."""
        self.scheduler.shutdown()
        logger.info("DevGuard scheduler stopped.")

    async def scan_recent_comments(self):
        """Job: Fetches recent articles, reviews their comments, and runs detection/enforcement."""
        logger.info("Starting background comment scan job...")
        db = SessionLocal()
        
        # Record scan entry
        scan_record = Scan(mode=self.config.get("mode", "detect"), status="running")
        db.add(scan_record)
        db.commit()

        users_scanned = 0
        bots_detected = 0

        try:
            # Get latest custom rules from DB
            custom_rules = db.query(Rule).filter(Rule.is_active == True).all()

            # 1. Fetch latest articles
            articles = await self.articles_api.get_latest_articles(per_page=15)
            
            # Map of username to (user_profile, list of comments) for batch evaluation
            users_to_evaluate = {}

            for art in articles:
                art_id = art.get("id")
                if not art_id:
                    continue
                    
                # 2. Fetch comments for this article
                comments = await self.comments_api.get_comments_by_article(art_id)
                for comment in comments:
                    comment_id = comment.get("id_code")
                    if not comment_id or comment_id in self.scanned_comment_ids:
                        continue
                        
                    author = comment.get("user", {})
                    username = author.get("username")
                    if not username:
                        continue
                        
                    if username not in users_to_evaluate:
                        users_to_evaluate[username] = {
                            "profile": author,
                            "comments": []
                        }
                    
                    users_to_evaluate[username]["comments"].append(comment)
                    self.scanned_comment_ids.add(comment_id)
                    
                    # Prevent cache from growing infinitely
                    if len(self.scanned_comment_ids) > 10000:
                        self.scanned_comment_ids.pop()

            # 3. Evaluate compiled users
            for username, data in users_to_evaluate.items():
                try:
                    # Retrieve full profile for details (e.g. following count, bio)
                    full_profile = await self.users_api.get_user_profile_by_username(username)
                    if not full_profile:
                        full_profile = data["profile"]
                        
                    # Run scanning engine
                    result = await self.engine.scan_user(
                        user_profile=full_profile,
                        comments=data["comments"],
                        custom_rules=custom_rules
                    )
                    
                    # Persist user / flag data
                    user_record = process_detection_result(db, scan_record.id, result, full_profile)
                    users_scanned += 1
                    
                    if result.verdict in ("likely_bot", "confirmed_bot"):
                        bots_detected += 1
                        # Trigger automated enforcement if execute mode is enabled
                        await self.executor.evaluate_and_enforce(db, self.users_api, user_record, result.risk_score)
                except Exception as e:
                    logger.error(f"Error scanning user {username} in job: {e}", exc_info=True)

            # Update scan record
            scan_record.completed_at = datetime.utcnow()
            scan_record.users_scanned = users_scanned
            scan_record.bots_detected = bots_detected
            scan_record.status = "completed"
            db.commit()
            logger.info(f"Comment scan job completed. Scanned: {users_scanned}, Bots: {bots_detected}")

        except Exception as e:
            logger.error(f"Error in comment scan job: {e}", exc_info=True)
            scan_record.completed_at = datetime.utcnow()
            scan_record.status = "failed"
            db.commit()
        finally:
            db.close()

    async def scan_new_followers(self):
        """Job: Fetches recent followers of the authenticated account and scans them."""
        logger.info("Starting background follower scan job...")
        db = SessionLocal()
        
        scan_record = Scan(mode=self.config.get("mode", "detect"), status="running")
        db.add(scan_record)
        db.commit()

        users_scanned = 0
        bots_detected = 0

        try:
            custom_rules = db.query(Rule).filter(Rule.is_active == True).all()
            
            # Fetch followers list
            followers = await self.followers_api.get_followers(per_page=50)
            
            for follower in followers:
                username = follower.get("username")
                if not username:
                    continue
                    
                try:
                    # Get full profile
                    full_profile = await self.users_api.get_user_profile_by_username(username)
                    if not full_profile:
                        full_profile = follower

                    # Follower has no recent comment context in this job, so scan empty comments list
                    result = await self.engine.scan_user(
                        user_profile=full_profile,
                        comments=[],
                        custom_rules=custom_rules
                    )
                    
                    user_record = process_detection_result(db, scan_record.id, result, full_profile)
                    users_scanned += 1
                    
                    if result.verdict in ("likely_bot", "confirmed_bot"):
                        bots_detected += 1
                        await self.executor.evaluate_and_enforce(db, self.users_api, user_record, result.risk_score)
                except Exception as e:
                    logger.error(f"Error scanning follower {username} in job: {e}")

            scan_record.completed_at = datetime.utcnow()
            scan_record.users_scanned = users_scanned
            scan_record.bots_detected = bots_detected
            scan_record.status = "completed"
            db.commit()
            logger.info(f"Follower scan job completed. Scanned: {users_scanned}, Bots: {bots_detected}")

        except Exception as e:
            logger.error(f"Error in follower scan job: {e}", exc_info=True)
            scan_record.completed_at = datetime.utcnow()
            scan_record.status = "failed"
            db.commit()
        finally:
            db.close()
