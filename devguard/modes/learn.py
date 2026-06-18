import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from devguard.database import Report, Rule, User, Flag
from devguard.api.users import UsersAPI
from devguard.api.comments import CommentsAPI
from devguard.api.articles import ArticlesAPI

logger = logging.getLogger("devguard.modes.learn")

class LearnModeController:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    async def ingest_report(
        self,
        db: Session,
        users_api: UsersAPI,
        comments_api: CommentsAPI,
        articles_api: ArticlesAPI,
        reported_username: str,
        reason: str,
        reporter: str = "community"
    ) -> Report:
        """Gathers data about a reported user and adds a Report record to the database."""
        logger.info(f"Ingesting report for {reported_username} by {reporter}. Reason: {reason}")
        
        # 1. Fetch reported user profile
        profile = {}
        try:
            profile = await users_api.get_user_profile_by_username(reported_username)
        except Exception as e:
            logger.error(f"Failed to fetch profile for reported user {reported_username}: {e}")

        comments = []
        user_id = profile.get("id")
        if user_id:
            # 2. Gather user comments
            # We can find articles written by the user or recent articles to scan for their comments,
            # or if the API doesn't allow user comment listings directly, we scan latest articles.
            # In Forem, to find comments by a user, we typically scan recent articles.
            # To be efficient, let's look up articles authored by this user, or scan the latest articles.
            try:
                user_articles = await articles_api.get_articles(username=reported_username, per_page=10)
                for art in user_articles:
                    art_comments = await comments_api.get_comments_by_article(art.get("id"))
                    # Filter comments authored by this user
                    for c in art_comments:
                        author = c.get("user", {})
                        if author.get("username") == reported_username:
                            comments.append({
                                "id": c.get("id_code"),
                                "body": c.get("body_html"),
                                "created_at": c.get("created_at")
                            })
            except Exception as e:
                logger.error(f"Error gathering comments for {reported_username}: {e}")

        # Assemble gathered data
        gathered_data = {
            "profile": profile,
            "comments": comments,
            "scan_time": datetime.utcnow().isoformat()
        }

        # Save report
        report = Report(
            reported_username=reported_username,
            reason=reason,
            reporter=reporter,
            status="pending",
        )
        report.gathered_data = gathered_data
        
        db.add(report)
        db.commit()
        return report

    def preview_rule_impact(
        self,
        db: Session,
        pattern_type: str,  # username_regex | content_regex | ip_range
        pattern: str
    ) -> Dict[str, Any]:
        """Tests a regex pattern against cached users/comments in the local DB.
        
        Shows what the impact would be before committing the rule.
        """
        matched_users = []
        whitelist_hits = []
        
        try:
            compiled_regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return {"error": f"Invalid regex pattern: {e}"}

        if pattern_type == "username_regex":
            users = db.query(User).all()
            for u in users:
                if compiled_regex.search(u.username):
                    matched_users.append(u.username)
                    if u.is_whitelisted:
                        whitelist_hits.append(u.username)

        elif pattern_type == "content_regex":
            # Scan flags/comments cached in flags table or user bio
            # In our DB, we cache comment flags. Let's look up users whose flag evidence matches
            flags = db.query(Flag).filter(Flag.detector == "content").all()
            for f in flags:
                evidence = f.evidence
                # Check if evidence contains a body or we search text fields
                for k, v in evidence.items():
                    if isinstance(v, str) and compiled_regex.search(v):
                        user = db.query(User).filter(User.id == f.user_id).first()
                        if user and user.username not in matched_users:
                            matched_users.append(user.username)
                            if user.is_whitelisted:
                                whitelist_hits.append(user.username)

        return {
            "total_matches": len(matched_users),
            "matched_usernames": matched_users[:50],  # cap list
            "whitelist_hits_count": len(whitelist_hits),
            "whitelist_hits": whitelist_hits,
            "false_positive_risk": "high" if len(whitelist_hits) > 0 else ("medium" if len(matched_users) > 10 else "low")
        }

    def commit_rule(
        self,
        db: Session,
        name: str,
        pattern_type: str,
        pattern: str,
        description: str
    ) -> Rule:
        """Saves a new custom detection rule and resolves pending reports matching the pattern."""
        rule = Rule(
            name=name,
            pattern_type=pattern_type,
            pattern=pattern,
            description=description,
            is_active=True
        )
        db.add(rule)
        
        # Resolve pending reports that match this rule
        compiled_regex = re.compile(pattern, re.IGNORECASE)
        pending_reports = db.query(Report).filter(Report.status == "pending").all()
        
        for rep in pending_reports:
            match = False
            if pattern_type == "username_regex":
                if compiled_regex.search(rep.reported_username):
                    match = True
            elif pattern_type == "content_regex":
                data = rep.gathered_data
                comments = data.get("comments", [])
                for c in comments:
                    body = c.get("body", "")
                    if compiled_regex.search(body):
                        match = True
                        break
                        
            if match:
                rep.status = "reviewed"

        db.commit()
        return rule
