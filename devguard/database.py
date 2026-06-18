import os
import json
from datetime import datetime
from typing import Generator
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

DATABASE_URL = os.environ.get("DEVGUARD_DB_URL", "sqlite:///data/devguard.db")

# Ensure data directory exists
data_dir = DATABASE_URL.replace("sqlite:///", "")
if "/" in data_dir or "\\" in data_dir:
    os.makedirs(os.path.dirname(data_dir), exist_ok=True)

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)  # Forem user ID
    username = Column(String, unique=True, index=True, nullable=False)
    name = Column(String)
    joined_at = Column(DateTime, default=datetime.utcnow)
    comment_count = Column(Integer, default=0)
    post_count = Column(Integer, default=0)
    followers_count = Column(Integer, default=0)
    following_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    verdict = Column(String, default="clean")  # clean, suspicious, likely_bot, confirmed_bot
    last_scanned_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_whitelisted = Column(Boolean, default=False)

    flags = relationship("Flag", back_populates="user", cascade="all, delete-orphan")
    actions = relationship("Action", back_populates="user", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    mode = Column(String, nullable=False)  # detect, execute, learn
    users_scanned = Column(Integer, default=0)
    bots_detected = Column(Integer, default=0)
    status = Column(String, default="running")  # running, completed, failed

    flags = relationship("Flag", back_populates="scan", cascade="all, delete-orphan")


class Flag(Base):
    __tablename__ = "flags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    detector = Column(String, nullable=False)  # content, profile, behavioral, fingerprint, ip_intel
    rule_name = Column(String, nullable=False)
    severity = Column(Float, nullable=False)  # 0.0 to 1.0
    description = Column(String)
    evidence_json = Column(Text)  # Serialized JSON evidence
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="flags")
    scan = relationship("Scan", back_populates="flags")

    @property
    def evidence(self):
        if self.evidence_json:
            try:
                return json.loads(self.evidence_json)
            except Exception:
                return {}
        return {}

    @evidence.setter
    def evidence(self, value):
        self.evidence_json = json.dumps(value)


class Action(Base):
    __tablename__ = "actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action_type = Column(String, nullable=False)  # suspend, unpublish, dry_run_suspend, dry_run_unpublish
    status = Column(String, nullable=False)  # success, failed, pending, rolled_back
    performed_at = Column(DateTime, default=datetime.utcnow)
    details = Column(String)

    user = relationship("User", back_populates="actions")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    reported_username = Column(String, nullable=False, index=True)
    reason = Column(String)
    reporter = Column(String, default="community")
    status = Column(String, default="pending")  # pending, reviewed, dismissed
    created_at = Column(DateTime, default=datetime.utcnow)
    gathered_data_json = Column(Text)  # JSON dump of gathered data (profile details, comments, etc.)

    @property
    def gathered_data(self):
        if self.gathered_data_json:
            try:
                return json.loads(self.gathered_data_json)
            except Exception:
                return {}
        return {}

    @gathered_data.setter
    def gathered_data(self, value):
        self.gathered_data_json = json.dumps(value)


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    pattern_type = Column(String, nullable=False)  # content_regex, username_regex, ip_range, asn
    pattern = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    description = Column(String)


class Fingerprint(Base):
    __tablename__ = "fingerprints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, index=True, nullable=True)
    session_id = Column(String, index=True, nullable=False)
    ip_address = Column(String)
    user_agent = Column(String)
    webdriver = Column(Boolean, default=False)
    cdp_artifacts = Column(Boolean, default=False)
    plugins_len = Column(Integer, default=0)
    languages = Column(String)
    canvas_hash = Column(String)
    webgl_renderer = Column(String)
    timezone = Column(String)
    screen_res = Column(String)
    raw_data_json = Column(Text)  # full payload json
    created_at = Column(DateTime, default=datetime.utcnow)

    @property
    def raw_data(self):
        if self.raw_data_json:
            try:
                return json.loads(self.raw_data_json)
            except Exception:
                return {}
        return {}

    @raw_data.setter
    def raw_data(self, value):
        self.raw_data_json = json.dumps(value)


class WhitelistEntry(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String)
    added_at = Column(DateTime, default=datetime.utcnow)


class ConfigOverride(Base):
    __tablename__ = "config_overrides"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String, unique=True, index=True, nullable=False)
    value = Column(String, nullable=False)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
