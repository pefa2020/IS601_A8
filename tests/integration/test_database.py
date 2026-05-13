import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine
from sqlalchemy.orm.session import Session
import importlib
import sys

DATABASE_MODULE = "app.database"

@pytest.fixture
def mock_settings(monkeypatch):
    """Fixture to mock the settings.DATABASE_URL before app.database is imported."""
    mock_url = "postgresql://user:password@localhost:5432/test_db"
    mock_settings = MagicMock()
    mock_settings.DATABASE_URL = mock_url
    # Ensure 'app.database' is not loaded
    if DATABASE_MODULE in sys.modules:
        del sys.modules[DATABASE_MODULE]
    # Patch settings in 'app.database'
    monkeypatch.setattr(f"{DATABASE_MODULE}.settings", mock_settings)
    return mock_settings

def reload_database_module():
    """Helper function to reload the database module after patches."""
    if DATABASE_MODULE in sys.modules:
        del sys.modules[DATABASE_MODULE]
    return importlib.import_module(DATABASE_MODULE)

def test_base_declaration(mock_settings):
    """Test that Base is an instance of declarative_base."""
    database = reload_database_module()
    Base = database.Base
    assert isinstance(Base, database.declarative_base().__class__)

def test_get_engine_success(mock_settings):
    """Test that get_engine returns a valid engine."""
    database = reload_database_module()
    engine = database.get_engine()
    assert isinstance(engine, Engine)

def test_get_engine_failure(mock_settings):
    """Test that get_engine raises an error if the engine cannot be created."""
    database = reload_database_module()
    with patch("app.database.create_engine", side_effect=SQLAlchemyError("Engine error")):
        with pytest.raises(SQLAlchemyError, match="Engine error"):
            database.get_engine()

def test_get_sessionmaker(mock_settings):
    """Test that get_sessionmaker returns a valid sessionmaker."""
    database = reload_database_module()
    engine = database.get_engine()
    SessionLocal = database.get_sessionmaker(engine)
    assert isinstance(SessionLocal, sessionmaker)


def test_database_command_covers_application_helpers(db_session, monkeypatch):
    """Exercise app branches included in the global coverage report."""
    import uuid
    from datetime import timedelta

    from fastapi import HTTPException

    import app.database as database
    import app.database_init as database_init
    from app.auth.dependencies import get_current_active_user, get_current_user
    from app.models.user import User
    from app.operations import add, divide, multiply, subtract
    from app.schemas.base import PasswordMixin, UserCreate, UserLogin
    from app.schemas.user import UserResponse

    assert add(2, 3) == 5
    assert subtract(5, 3) == 2
    assert multiply(4, 3) == 12
    assert divide(9, 3) == 3
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide(1, 0)

    class FakeSession:
        closed = False

        def close(self):
            self.closed = True

    fake_session = FakeSession()
    monkeypatch.setattr(database, "SessionLocal", lambda: fake_session)
    db_generator = database.get_db()
    assert next(db_generator) is fake_session
    with pytest.raises(StopIteration):
        next(db_generator)
    assert fake_session.closed is True

    calls = []

    class FakeMetadata:
        def create_all(self, bind):
            calls.append(("create_all", bind))

        def drop_all(self, bind):
            calls.append(("drop_all", bind))

    class FakeBase:
        metadata = FakeMetadata()

    fake_engine = object()
    monkeypatch.setattr(database_init, "Base", FakeBase)
    monkeypatch.setattr(database_init, "engine", fake_engine)
    database_init.init_db()
    database_init.drop_db()
    assert calls == [("create_all", fake_engine), ("drop_all", fake_engine)]

    valid_data = {
        "first_name": "Valid",
        "last_name": "User",
        "email": "valid_database_schema@example.com",
        "username": "validdatabaseschema",
        "password": "Password1",
    }
    assert UserCreate.model_validate(valid_data).password == "Password1"
    assert UserLogin.model_validate({"username": "validdatabaseschema", "password": "Password1"}).username == "validdatabaseschema"

    invalid_passwords = [
        ("short", "at least 6"),
        ("password1", "uppercase"),
        ("PASSWORD1", "lowercase"),
        ("Password", "digit"),
    ]
    for password, message in invalid_passwords:
        with pytest.raises(ValueError, match=message):
            PasswordMixin.validate_password({"password": password})

    suffix = uuid.uuid4().hex[:8]
    password = "SecurePass123"
    user_data = {
        "first_name": "Auth",
        "last_name": "User",
        "email": f"database_auth_{suffix}@example.com",
        "username": f"database_auth_{suffix}",
        "password": password,
    }

    user = User.register(db_session, user_data)
    db_session.commit()
    db_session.refresh(user)

    assert repr(user) == f"<User(name=Auth User, email={user.email})>"
    assert user.password != password
    assert user.verify_password(password) is True
    assert User.authenticate(db_session, "missing-user", password) is None

    token = User.create_access_token({"sub": str(user.id)}, expires_delta=timedelta(minutes=5))
    assert User.verify_token(token) == user.id
    assert User.verify_token("bad.token.value") is None
    assert User.verify_token(User.create_access_token({})) is None

    auth_result = User.authenticate(db_session, user.username, password)
    assert auth_result["token_type"] == "bearer"
    assert auth_result["user"]["username"] == user.username

    with pytest.raises(ValueError, match="at least 6"):
        User.register(db_session, {"password": "short"})

    duplicate_data = user_data | {
        "username": f"database_duplicate_{suffix}",
        "password": "Password1",
    }
    with pytest.raises(ValueError, match="already exists"):
        User.register(db_session, duplicate_data)

    invalid_schema_data = user_data | {
        "email": "not-an-email",
        "username": f"database_invalid_{suffix}",
        "password": "Password1",
    }
    with pytest.raises(ValueError):
        User.register(db_session, invalid_schema_data)

    current_user = get_current_user(db_session, token)
    assert current_user.id == user.id
    assert get_current_active_user(current_user) is current_user

    with pytest.raises(HTTPException) as invalid_token:
        get_current_user(db_session, "not-a-token")
    assert invalid_token.value.status_code == 401

    missing_user_token = User.create_access_token({"sub": str(uuid.uuid4())})
    with pytest.raises(HTTPException) as missing_user:
        get_current_user(db_session, missing_user_token)
    assert missing_user.value.status_code == 401

    inactive_user = UserResponse.model_validate(user)
    inactive_user.is_active = False
    with pytest.raises(HTTPException) as inactive:
        get_current_active_user(inactive_user)
    assert inactive.value.status_code == 400
