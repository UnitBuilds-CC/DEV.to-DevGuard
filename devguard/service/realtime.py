import logging
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, BackgroundTasks, Request, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from devguard.database import SessionLocal, get_db, Fingerprint, Rule, User
from devguard.detection.engine import DetectionEngine
from devguard.modes.detect import process_detection_result
from devguard.modes.execute import ExecutionController
from devguard.api import ForemClient, UsersAPI, CommentsAPI

class CommentValidationRequest(BaseModel):
    username: str
    body: str
    ip_address: Optional[str] = None
    session_id: Optional[str] = None

class UserValidationRequest(BaseModel):
    username: str
    name: str
    email: str
    ip_address: Optional[str] = None
    session_id: Optional[str] = None

logger = logging.getLogger("devguard.service.realtime")
router = APIRouter(prefix="/api/realtime", tags=["realtime"])

# Helper to run an immediate user audit in the background
async def audit_user_realtime(
    username: str,
    ip_address: str,
    fp_data: Dict[str, Any],
    config: Dict[str, Any]
):
    logger.info(f"Triggering real-time audit for user: {username}")
    db = SessionLocal() # Get a direct DB session for background task
    
    try:
        # Create Forem API Client
        api_config = config.get("api", {})
        client = ForemClient(
            base_url=api_config.get("base_url", "https://dev.to/api"),
            api_key=api_config.get("api_key", ""),
            rate_limit_per_sec=api_config.get("rate_limit", 10)
        )
        users_api = UsersAPI(client)
        comments_api = CommentsAPI(client)
        
        # 1. Fetch profile and recent comments
        profile = await users_api.get_user_profile_by_username(username)
        if not profile:
            logger.warning(f"Could not fetch profile for real-time audit of {username}")
            return

        # Fetch comments from latest articles to scan for their messages
        comments = []
        try:
            # We can also get comments if we scan articles written by them
            # or simply use empty comments list as we have the fingerprint payload
            pass
        except Exception:
            pass

        # 2. Run detection engine
        engine = DetectionEngine(config)
        custom_rules = db.query(Rule).filter(Rule.is_active == True).all()
        
        result = await engine.scan_user(
            user_profile=profile,
            comments=comments,
            fingerprint_data=fp_data,
            ip_address=ip_address,
            custom_rules=custom_rules
        )

        # 3. Save result and run execution mode
        user_record = process_detection_result(db, None, result, profile)
        executor = ExecutionController(config)
        await executor.evaluate_and_enforce(db, users_api, user_record, result.risk_score)
        
        await client.close()
    except Exception as e:
        logger.error(f"Error in real-time background audit for {username}: {e}", exc_info=True)
    finally:
        db.close()


@router.post("/fingerprint")
async def collect_fingerprint(
    payload: Dict[str, Any],
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Receives browser fingerprint payload from client collector.js."""
    session_id = payload.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session_id")

    username = payload.get("username")
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # Save to Database
    db_fp = Fingerprint(
        username=username,
        session_id=session_id,
        ip_address=ip_address,
        user_agent=user_agent,
        webdriver=payload.get("webdriver", False),
        cdp_artifacts=payload.get("cdp_artifacts", False),
        plugins_len=int(payload.get("plugins_len", 0)),
        languages=str(payload.get("languages", "")),
        canvas_hash=payload.get("canvas_hash"),
        webgl_renderer=payload.get("webgl_renderer"),
        timezone=payload.get("timezone"),
        screen_res=payload.get("screen_res"),
    )
    db_fp.raw_data = payload
    
    db.add(db_fp)
    db.commit()

    logger.info(f"Fingerprint logged for session {session_id} (user: {username}, IP: {ip_address})")

    # If the fingerprint is associated with a logged-in user, run real-time audit in background
    if username:
        # Access the app config from request state
        config = getattr(request.app, "state_config", {})
        background_tasks.add_task(
            audit_user_realtime,
            username=username,
            ip_address=ip_address,
            fp_data=payload,
            config=config
        )

    return {"status": "success", "session_id": session_id}


@router.post("/event")
async def receive_forem_event(
    event: Dict[str, Any],
    request: Request,
    background_tasks: BackgroundTasks
):
    """Receives webhook events (comments, registrations) from Forem/DEV.to."""
    event_type = event.get("type")
    logger.info(f"Received Forem webhook event: {event_type}")

    config = getattr(request.app, "state_config", {})
    
    # Process webhook events
    # Example comment event: {type: "comment_created", author: "username"}
    if event_type == "comment_created" or event_type == "user_registered":
        author_username = event.get("author") or event.get("username")
        if author_username:
            background_tasks.add_task(
                audit_user_realtime,
                username=author_username,
                ip_address=event.get("ip_address", "unknown"),
                fp_data={},
                config=config
            )

    return {"status": "received"}


@router.post("/validate-comment")
async def validate_comment(
    payload: CommentValidationRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Synchronously validates comment body, author, IP, and browser fingerprint."""
    config = getattr(request.app, "state_config", {})
    
    # 1. Fetch fingerprint telemetry if session_id is provided
    fp_data = None
    if payload.session_id:
        fp_rec = db.query(Fingerprint).filter(Fingerprint.session_id == payload.session_id).order_by(Fingerprint.created_at.desc()).first()
        if fp_rec:
            fp_data = fp_rec.raw_data

    # 2. Retrieve user profile (check DB cache or fetch from Forem API)
    cached_user = db.query(User).filter(User.username == payload.username).first()
    profile = {}
    if cached_user:
        profile = {
            "username": cached_user.username,
            "id": cached_user.id,
            "name": cached_user.name,
            "followers_count": cached_user.followers_count,
            "following_count": cached_user.following_count,
            "post_count": cached_user.post_count,
            "comment_count": cached_user.comment_count,
            "created_at": cached_user.joined_at.isoformat() if cached_user.joined_at else None
        }
    else:
        api_config = config.get("api", {})
        client = ForemClient(
            base_url=api_config.get("base_url", "https://dev.to/api"),
            api_key=api_config.get("api_key", ""),
            rate_limit_per_sec=api_config.get("rate_limit", 10)
        )
        users_api = UsersAPI(client)
        try:
            profile = await users_api.get_user_profile_by_username(payload.username)
        except Exception:
            pass
        finally:
            await client.close()
        
        if not profile:
            profile = {
                "username": payload.username,
                "id": None,
                "created_at": datetime.utcnow().isoformat()
            }

    # 3. Run Detection Engine
    engine = DetectionEngine(config)
    custom_rules = db.query(Rule).filter(Rule.is_active == True).all()
    
    result = await engine.scan_user(
        user_profile=profile,
        comments=[{"body": payload.body}],
        fingerprint_data=fp_data,
        ip_address=payload.ip_address,
        custom_rules=custom_rules
    )

    # 4. Cache verdict / user record
    process_detection_result(db, None, result, profile)

    return {
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "is_bot": result.verdict == "confirmed_bot",
        "flags": [f.model_dump() for f in result.flags]
    }


@router.post("/validate-user")
async def validate_user(
    payload: UserValidationRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Synchronously validates user registration details, IP, and browser fingerprint."""
    config = getattr(request.app, "state_config", {})
    
    # 1. Fetch fingerprint telemetry if session_id is provided
    fp_data = None
    if payload.session_id:
        fp_rec = db.query(Fingerprint).filter(Fingerprint.session_id == payload.session_id).order_by(Fingerprint.created_at.desc()).first()
        if fp_rec:
            fp_data = fp_rec.raw_data

    # 2. Mock profile dictionary for unregistered user
    profile = {
        "username": payload.username,
        "name": payload.name,
        "email": payload.email,
        "id": None,
        "created_at": datetime.utcnow().isoformat()
    }

    # 3. Run Detection Engine
    engine = DetectionEngine(config)
    custom_rules = db.query(Rule).filter(Rule.is_active == True).all()
    
    result = await engine.scan_user(
        user_profile=profile,
        comments=[],
        fingerprint_data=fp_data,
        ip_address=payload.ip_address,
        custom_rules=custom_rules
    )

    # 4. Cache verdict / user record
    process_detection_result(db, None, result, profile)

    return {
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "is_bot": result.verdict == "confirmed_bot",
        "flags": [f.model_dump() for f in result.flags]
    }
