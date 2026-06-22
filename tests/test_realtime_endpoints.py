import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from devguard.dashboard.app import app
from devguard.database import get_db, Base, Fingerprint, User
from devguard.detection.scoring import DetectionResult, DetectionFlag

@pytest.fixture
def test_db():
    """Creates a fresh in-memory SQLite database for the duration of the test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    yield TestingSessionLocal
    
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client(test_db):
    # Override get_db dependency to yield a session from test_db per request
    def override_get_db():
        db = test_db()
        try:
            yield db
        finally:
            db.close()
            
    app.dependency_overrides[get_db] = override_get_db
    
    # Setup standard app state config for tests
    app.state_config = {
        "api": {
            "base_url": "https://dev.to/api",
            "api_key": "test_key",
            "rate_limit": 10
        },
        "mode": "detect",
        "thresholds": {
            "suspicious": 0.4,
            "likely_bot": 0.7,
            "confirmed_bot": 0.9
        },
        "weights": {
            "content": 0.25,
            "profile": 0.20,
            "behavioral": 0.20,
            "fingerprint": 0.20,
            "ip_intel": 0.15
        }
    }
    
    with TestClient(app) as c:
        yield c
        
    app.dependency_overrides.clear()

def test_validate_comment_clean(client, test_db):
    # Seed an established clean user in database cache to avoid profile flags
    db = test_db()
    user = User(
        id=9999,
        username="clean_user",
        name="Clean User",
        joined_at=datetime.utcnow() - timedelta(days=15),
        comment_count=20,
        post_count=10,
        followers_count=100,
        following_count=50,
        risk_score=0.0,
        verdict="clean",
        is_whitelisted=False
    )
    db.add(user)
    db.commit()
    db.close()

    payload = {
        "username": "clean_user",
        "body": "This is a very helpful comment, thank you for writing this!",
        "ip_address": "127.0.0.1"
    }
    
    response = client.post("/api/realtime/validate-comment", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["verdict"] == "clean"
    assert res_data["is_bot"] is False
    assert res_data["risk_score"] < 0.4

def test_validate_comment_spam_content(client, test_db):
    # Seed established user
    db = test_db()
    user = User(
        id=9999,
        username="spammer1",
        name="Spammer One",
        joined_at=datetime.utcnow() - timedelta(days=15),
        comment_count=20,
        post_count=10,
        followers_count=100,
        following_count=50,
        risk_score=0.0,
        verdict="clean"
    )
    db.add(user)
    db.commit()
    db.close()

    payload = {
        "username": "spammer1",
        "body": "Buy cheap stuff at spamdomain.com now!!! Click here: http://bit.ly/spam",
        "ip_address": "127.0.0.1"
    }
    
    response = client.post("/api/realtime/validate-comment", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["risk_score"] > 0.0

def test_validate_comment_bot_fingerprint(client, test_db):
    # Seed established user and their bot fingerprint
    db = test_db()
    user = User(
        id=8888,
        username="bot_user",
        name="Bot User",
        joined_at=datetime.utcnow() - timedelta(days=15),
        comment_count=20,
        post_count=10,
        followers_count=100,
        following_count=50,
        risk_score=0.0,
        verdict="clean"
    )
    fp = Fingerprint(
        username="bot_user",
        session_id="session_bot_123",
        ip_address="192.168.1.5",
        user_agent="Mozilla/5.0",
        webdriver=True, # WebDriver is active!
        cdp_artifacts=True,
        plugins_len=0
    )
    fp.raw_data = {"webdriver": True, "cdp_artifacts": True}
    db.add_all([user, fp])
    db.commit()
    db.close()
    
    payload = {
        "username": "bot_user",
        "body": "Hello, nice post.",
        "ip_address": "192.168.1.5",
        "session_id": "session_bot_123"
    }
    
    response = client.post("/api/realtime/validate-comment", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["verdict"] in ("likely_bot", "confirmed_bot")

def test_validate_user_registration_clean(client):
    # Brand new registration payload will trigger new_account and incomplete_profile,
    # resulting in a 0.55 suspicious score, but it is NOT flagged as a bot.
    payload = {
        "username": "normal_new_user",
        "name": "Jane Doe",
        "email": "jane@example.com",
        "ip_address": "127.0.0.1"
    }
    
    response = client.post("/api/realtime/validate-user", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["is_bot"] is False
    assert res_data["verdict"] == "suspicious"
    assert res_data["risk_score"] == 0.55

def test_validate_user_registration_bot_fingerprint(client, test_db):
    # Seed the database with a bot fingerprint
    db = test_db()
    fp = Fingerprint(
        username="bot_signup",
        session_id="session_signup_123",
        ip_address="1.2.3.4",
        user_agent="Mozilla/5.0",
        webdriver=True
    )
    fp.raw_data = {"webdriver": True}
    db.add(fp)
    db.commit()
    db.close()
    
    payload = {
        "username": "bot_signup",
        "name": "Robot",
        "email": "bot@spam.com",
        "ip_address": "1.2.3.4",
        "session_id": "session_signup_123"
    }
    
    response = client.post("/api/realtime/validate-user", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["verdict"] in ("likely_bot", "confirmed_bot")
