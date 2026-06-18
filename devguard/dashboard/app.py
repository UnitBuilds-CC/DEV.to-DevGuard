import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel

from devguard.database import (
    get_db, SessionLocal, User, Flag, Scan, Action, Report, Rule, WhitelistEntry, init_db
)
from devguard.config import load_config
from devguard.service.scheduler import DevGuardScheduler
from devguard.service.realtime import router as realtime_router
from devguard.service.worker import DevGuardWorker

logger = logging.getLogger("devguard.dashboard.app")

class RuleCreate(BaseModel):
    name: str
    pattern_type: str
    pattern: str
    description: Optional[str] = None

class ReportReview(BaseModel):
    action: str  # approve | dismiss
    rule_name: Optional[str] = None
    pattern_type: Optional[str] = None
    pattern: Optional[str] = None
    description: Optional[str] = None

class WhitelistCreate(BaseModel):
    username: str
    reason: Optional[str] = None

class ScanRequest(BaseModel):
    username: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup hook
    logger.info("Initializing DevGuard dashboard database...")
    init_db()
    
    # Load config and attach to app state
    config = load_config("config.yaml")
    app.state_config = config
    
    # Initialize and start background scheduler
    logger.info("Starting DevGuard background scheduler...")
    scheduler = DevGuardScheduler(config)
    scheduler.start()
    app.scheduler = scheduler
    
    yield
    
    # Shutdown hook
    logger.info("Shutting down DevGuard background scheduler...")
    if hasattr(app, "scheduler"):
        app.scheduler.stop()
        await app.scheduler.client.close()

app = FastAPI(
    title="DevGuard Dashboard",
    description="Anti-bot dashboard for DEV.to",
    version="0.1.0",
    lifespan=lifespan
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include real-time endpoint router
app.include_router(realtime_router)

# ----------------- Dashboard JSON API -----------------

@app.get("/api/overview")
async def get_overview(db: Session = Depends(get_db)):
    """Returns aggregated high-level statistics for the dashboard."""
    total_users = db.query(User).count()
    suspicious = db.query(User).filter(User.verdict == "suspicious").count()
    likely_bots = db.query(User).filter(User.verdict == "likely_bot").count()
    confirmed_bots = db.query(User).filter(User.verdict == "confirmed_bot").count()
    suspended = db.query(User).filter(User.verdict == "suspended").count()
    
    total_flags = db.query(Flag).count()
    total_scans = db.query(Scan).count()
    total_actions = db.query(Action).count()
    pending_reports = db.query(Report).filter(Report.status == "pending").count()
    
    # Calculate detections in last 24 hours
    one_day_ago = datetime.utcnow() - timedelta(days=1)
    recent_detections = db.query(User).filter(
        User.last_scanned_at >= one_day_ago,
        User.verdict.in_(["likely_bot", "confirmed_bot"])
    ).count()

    # Get last scan details
    last_scan = db.query(Scan).order_by(Scan.started_at.desc()).first()
    last_scan_time = last_scan.started_at.isoformat() if last_scan else None
    
    return {
        "stats": {
            "users_scanned": total_users,
            "suspicious": suspicious,
            "likely_bots": likely_bots,
            "confirmed_bots": confirmed_bots,
            "suspended": suspended,
            "total_flags": total_flags,
            "total_scans": total_scans,
            "total_actions": total_actions,
            "pending_reports": pending_reports,
            "recent_detections_24h": recent_detections
        },
        "last_scan_time": last_scan_time,
        "scheduler_active": True
    }


@app.get("/api/flagged")
async def get_flagged_users(db: Session = Depends(get_db)):
    """Lists all flagged users sorted by risk score."""
    users = db.query(User).filter(User.verdict != "clean").order_by(User.risk_score.desc()).all()
    
    result = []
    for u in users:
        # Fetch flags associated with this user
        flags = db.query(Flag).filter(Flag.user_id == u.id).all()
        flag_list = []
        for f in flags:
            flag_list.append({
                "detector": f.detector,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence
            })
            
        result.append({
            "id": u.id,
            "username": u.username,
            "name": u.name,
            "risk_score": u.risk_score,
            "verdict": u.verdict,
            "joined_at": u.joined_at.isoformat() if u.joined_at else None,
            "followers_count": u.followers_count,
            "following_count": u.following_count,
            "post_count": u.post_count,
            "comment_count": u.comment_count,
            "last_scanned_at": u.last_scanned_at.isoformat() if u.last_scanned_at else None,
            "flags": flag_list
        })
    return result


@app.get("/api/reports")
async def get_pending_reports(db: Session = Depends(get_db)):
    """Returns community reports queue."""
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    result = []
    for r in reports:
        result.append({
            "id": r.id,
            "reported_username": r.reported_username,
            "reason": r.reason,
            "reporter": r.reporter,
            "status": r.status,
            "created_at": r.created_at.isoformat(),
            "gathered_data": r.gathered_data
        })
    return result


@app.post("/api/reports/{report_id}/review")
async def review_report(
    report_id: int,
    review: ReportReview,
    db: Session = Depends(get_db)
):
    """Reviews and resolves a community report."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if review.action == "dismiss":
        report.status = "dismissed"
        db.commit()
        return {"status": "dismissed"}

    elif review.action == "approve":
        if not review.rule_name or not review.pattern_type or not review.pattern:
            raise HTTPException(status_code=400, detail="Missing custom rule definition details")

        # Create the custom rule
        from devguard.modes.learn import LearnModeController
        learn_controller = LearnModeController(app.state_config)
        
        try:
            learn_controller.commit_rule(
                db=db,
                name=review.rule_name,
                pattern_type=review.pattern_type,
                pattern=review.pattern,
                description=review.description or f"Created from report against {report.reported_username}"
            )
            report.status = "reviewed"
            db.commit()
            return {"status": "approved_and_rule_created"}
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Failed to commit rule: {str(e)}")
            
    raise HTTPException(status_code=400, detail="Invalid action")


@app.get("/api/rules")
async def get_rules(db: Session = Depends(get_db)):
    """Lists all custom detection rules."""
    rules = db.query(Rule).all()
    return [{
        "id": r.id,
        "name": r.name,
        "pattern_type": r.pattern_type,
        "pattern": r.pattern,
        "is_active": r.is_active,
        "created_at": r.created_at.isoformat(),
        "description": r.description
    } for r in rules]


@app.post("/api/rules")
async def create_rule(rule_in: RuleCreate, db: Session = Depends(get_db)):
    """Creates a new custom rule."""
    existing = db.query(Rule).filter(Rule.name == rule_in.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule name already exists")
        
    db_rule = Rule(
        name=rule_in.name,
        pattern_type=rule_in.pattern_type,
        pattern=rule_in.pattern,
        description=rule_in.description,
        is_active=True
    )
    db.add(db_rule)
    db.commit()
    return {"status": "success", "id": db_rule.id}


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """Deletes a custom rule."""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"status": "success"}


@app.get("/api/whitelist")
async def get_whitelist(db: Session = Depends(get_db)):
    """Lists all whitelisted users."""
    entries = db.query(WhitelistEntry).all()
    return [{
        "username": e.username,
        "reason": e.reason,
        "added_at": e.added_at.isoformat()
    } for e in entries]


@app.post("/api/whitelist")
async def add_to_whitelist(entry_in: WhitelistCreate, db: Session = Depends(get_db)):
    """Adds a user to the whitelist."""
    existing = db.query(WhitelistEntry).filter(WhitelistEntry.username == entry_in.username).first()
    if existing:
        return {"status": "already_whitelisted"}
        
    entry = WhitelistEntry(
        username=entry_in.username,
        reason=entry_in.reason or "Added via Web Dashboard"
    )
    
    # Also update the user verdict cache if present
    cached_user = db.query(User).filter(User.username == entry_in.username).first()
    if cached_user:
        cached_user.is_whitelisted = True
        cached_user.verdict = "clean"
        cached_user.risk_score = 0.0
        
    db.add(entry)
    db.commit()
    return {"status": "success"}


@app.delete("/api/whitelist/{username}")
async def remove_from_whitelist(username: str, db: Session = Depends(get_db)):
    """Removes a user from the whitelist."""
    entry = db.query(WhitelistEntry).filter(WhitelistEntry.username == username).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")
        
    db.delete(entry)
    
    # Update the user verdict cache if present
    cached_user = db.query(User).filter(User.username == username).first()
    if cached_user:
        cached_user.is_whitelisted = False
        
    db.commit()
    return {"status": "success"}


@app.post("/api/scan-user")
async def scan_user_manually(req: ScanRequest):
    """Triggers an immediate scan of a user and returns results."""
    # Read config from state_config
    config = getattr(app, "state_config", {})
    worker = DevGuardWorker(config)
    result = await worker.scan_single_user_now(req.username)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/settings")
async def get_settings():
    """Returns active config settings."""
    config = getattr(app, "state_config", {})
    # Strip sensitive key
    safe_config = config.copy()
    if "api" in safe_config:
        safe_config["api"] = safe_config["api"].copy()
        if "api_key" in safe_config["api"]:
            key = safe_config["api"]["api_key"]
            safe_config["api"]["api_key"] = f"***{key[-4:]}" if len(key) > 4 else "***"
    return safe_config

# Serve frontend static files
# Make sure this is registered last so it doesn't shadow API routes
app.mount("/", StaticFiles(directory="devguard/dashboard/static", html=True), name="static")
