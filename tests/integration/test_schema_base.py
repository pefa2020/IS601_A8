import pytest
import uuid
from datetime import timedelta
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

import app.database as database
import app.database_init as database_init
from app.auth.dependencies import get_current_active_user, get_current_user
from app.models.user import User
from app.operations import add, divide, multiply, subtract
from app.schemas.base import UserBase, PasswordMixin, UserCreate, UserLogin
from app.schemas.user import UserResponse


def test_user_base_valid():
    """Test UserBase with valid data."""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
    }
    user = UserBase(**data)
    assert user.first_name == "John"
    assert user.email == "john.doe@example.com"


def test_user_base_invalid_email():
    """Test UserBase with invalid email."""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "invalid-email",
        "username": "johndoe",
    }
    with pytest.raises(ValidationError):
        UserBase(**data)


def test_password_mixin_valid():
    """Test PasswordMixin with valid password."""
    data = {"password": "SecurePass123"}
    password_mixin = PasswordMixin(**data)
    assert password_mixin.password == "SecurePass123"


def test_password_mixin_invalid_short_password():
    """Test PasswordMixin with short password."""
    data = {"password": "short"}
    with pytest.raises(ValidationError):
        PasswordMixin(**data)


def test_password_mixin_no_uppercase():
    """Test PasswordMixin with no uppercase letter."""
    data = {"password": "lowercase1"}
    with pytest.raises(ValidationError, match="Password must contain at least one uppercase letter"):
        PasswordMixin(**data)


def test_password_mixin_no_lowercase():
    """Test PasswordMixin with no lowercase letter."""
    data = {"password": "UPPERCASE1"}
    with pytest.raises(ValidationError, match="Password must contain at least one lowercase letter"):
        PasswordMixin(**data)


def test_password_mixin_no_digit():
    """Test PasswordMixin with no digit."""
    data = {"password": "NoDigitsHere"}
    with pytest.raises(ValidationError, match="Password must contain at least one digit"):
        PasswordMixin(**data)


def test_user_create_valid():
    """Test UserCreate with valid data."""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "SecurePass123",
    }
    user_create = UserCreate(**data)
    assert user_create.username == "johndoe"
    assert user_create.password == "SecurePass123"


def test_user_create_invalid_password():
    """Test UserCreate with invalid password."""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "short",
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)


def test_user_login_valid():
    """Test UserLogin with valid data."""
    data = {"username": "johndoe", "password": "SecurePass123"}
    user_login = UserLogin(**data)
    assert user_login.username == "johndoe"


def test_user_login_invalid_username():
    """Test UserLogin with short username."""
    data = {"username": "jd", "password": "SecurePass123"}
    with pytest.raises(ValidationError):
        UserLogin(**data)


def test_user_login_invalid_password():
    """Test UserLogin with invalid password."""
    data = {"username": "johndoe", "password": "short"}
    with pytest.raises(ValidationError):
        UserLogin(**data)


def test_schema_base_command_covers_application_helpers(db_session, monkeypatch):
    """Exercise app branches included in the global coverage report."""
    assert add(2, 3) == 5
    assert subtract(5, 3) == 2
    assert multiply(4, 3) == 12
    assert divide(9, 3) == 3
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide(1, 0)

    def raise_sqlalchemy_error(*args, **kwargs):
        raise SQLAlchemyError("engine failed")

    monkeypatch.setattr(database, "create_engine", raise_sqlalchemy_error)
    with pytest.raises(SQLAlchemyError, match="engine failed"):
        database.get_engine("postgresql://example")

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

    suffix = uuid.uuid4().hex[:8]
    password = "SecurePass123"
    user_data = {
        "first_name": "Auth",
        "last_name": "User",
        "email": f"schema_auth_{suffix}@example.com",
        "username": f"schema_auth_{suffix}",
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
        "username": f"schema_duplicate_{suffix}",
        "password": "Password1",
    }
    with pytest.raises(ValueError, match="already exists"):
        User.register(db_session, duplicate_data)

    invalid_schema_data = user_data | {
        "email": "not-an-email",
        "username": f"schema_invalid_{suffix}",
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

