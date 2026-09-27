import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.security import AETHER_API_KEY, RateLimitMiddleware

# The entire suite runs against the offline intel corpus. Setting this before
# any test imports the app guarantees no test can reach the network, even when
# a developer happens to have SHODAN_API_KEY exported in their shell.
os.environ["AETHER_INTEL_MODE"] = "mock"
os.environ.setdefault("AETHER_ACTIVE_PROBE_ENABLED", "false")


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # single shared connection so :memory: persists across requests
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    RateLimitMiddleware.reset_limits()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, headers={"X-AETHER-KEY": AETHER_API_KEY}) as c:
        yield c
    app.dependency_overrides.clear()
    RateLimitMiddleware.reset_limits()


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()

