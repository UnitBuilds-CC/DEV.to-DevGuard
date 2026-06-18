import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from devguard.database import Base

@pytest.fixture(scope="function")
def db_session():
    """Provides an in-memory SQLite database session for unit tests."""
    engine = create_engine("sqlite:///:memory:")
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
