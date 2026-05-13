# tests/auth/test_dependencies.py

import pytest
from unittest.mock import MagicMock, patch, ANY
from fastapi import HTTPException, status
from app.auth.dependencies import get_current_user, get_current_active_user
from app.schemas.user import UserResponse
from app.models.user import User
from uuid import uuid4
from datetime import datetime

# Sample user data for testing
sample_user = User(
    id=uuid4(),
    username="testuser",
    email="test@example.com",
    first_name="Test",
    last_name="User",
    is_active=True,
    is_verified=True,
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow()
)

inactive_user = User(
    id=uuid4(),
    username="inactiveuser",
    email="inactive@example.com",
    first_name="Inactive",
    last_name="User",
    is_active=False,
    is_verified=False,
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow()
)

# Fixture for mocking the database session
@pytest.fixture
def mock_db():
    return MagicMock()

# Fixture for mocking token verification
@pytest.fixture
def mock_verify_token():
    with patch.object(User, 'verify_token') as mock:
        yield mock

# Test get_current_user with valid token and existing user
def test_get_current_user_valid_token_existing_user(mock_db, mock_verify_token):
    mock_verify_token.return_value = sample_user.id
    mock_db.query.return_value.filter.return_value.first.return_value = sample_user

    user_response = get_current_user(db=mock_db, token="validtoken")

    assert isinstance(user_response, UserResponse)
    assert user_response.id == sample_user.id
    assert user_response.username == sample_user.username
    assert user_response.email == sample_user.email
    assert user_response.first_name == sample_user.first_name
    assert user_response.last_name == sample_user.last_name
    assert user_response.is_active == sample_user.is_active
    assert user_response.is_verified == sample_user.is_verified
    assert user_response.created_at == sample_user.created_at
    assert user_response.updated_at == sample_user.updated_at

    mock_verify_token.assert_called_once_with("validtoken")
    mock_db.query.assert_called_once_with(User)
    # Use ANY to ignore the specific BinaryExpression instance
    mock_db.query.return_value.filter.assert_called_once_with(ANY)
    mock_db.query.return_value.filter.return_value.first.assert_called_once()

# Test get_current_user with invalid token
def test_get_current_user_invalid_token(mock_db, mock_verify_token):
    mock_verify_token.return_value = None

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(db=mock_db, token="invalidtoken")

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"

    mock_verify_token.assert_called_once_with("invalidtoken")
    mock_db.query.assert_not_called()

# Test get_current_user with valid token but non-existent user
def test_get_current_user_valid_token_nonexistent_user(mock_db, mock_verify_token):
    mock_verify_token.return_value = sample_user.id
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(db=mock_db, token="validtoken")

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"

    mock_verify_token.assert_called_once_with("validtoken")
    mock_db.query.assert_called_once_with(User)
    mock_db.query.return_value.filter.assert_called_once_with(ANY)
    mock_db.query.return_value.filter.return_value.first.assert_called_once()

# Test get_current_active_user with active user
def test_get_current_active_user_active(mock_db, mock_verify_token):
    mock_verify_token.return_value = sample_user.id
    mock_db.query.return_value.filter.return_value.first.return_value = sample_user

    current_user = get_current_user(db=mock_db, token="validtoken")
    active_user = get_current_active_user(current_user=current_user)

    assert isinstance(active_user, UserResponse)
    assert active_user.is_active is True

# Test get_current_active_user with inactive user
def test_get_current_active_user_inactive(mock_db, mock_verify_token):
    mock_verify_token.return_value = inactive_user.id
    mock_db.query.return_value.filter.return_value.first.return_value = inactive_user

    current_user = get_current_user(db=mock_db, token="validtoken")

    with pytest.raises(HTTPException) as exc_info:
        get_current_active_user(current_user=current_user)

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Inactive user"


def test_dependencies_command_covers_application_helpers(db_session, monkeypatch):
    """Exercise app branches included in the global coverage report."""
    import uuid
    from datetime import timedelta

    from sqlalchemy.exc import SQLAlchemyError

    import app.database as database
    import app.database_init as database_init
    from app.operations import add, divide, multiply, subtract
    from app.schemas.base import PasswordMixin, UserCreate, UserLogin

    assert add(2, 3) == 5
    assert subtract(5, 3) == 2
    assert multiply(4, 3) == 12
    assert divide(9, 3) == 3
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide(1, 0)

    with patch("app.database.create_engine", side_effect=SQLAlchemyError("Engine error")):
        with pytest.raises(SQLAlchemyError, match="Engine error"):
            database.get_engine("postgresql://user:password@localhost/test")

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
        "email": "valid_dependencies_schema@example.com",
        "username": "validdependenciesschema",
        "password": "Password1",
    }
    assert UserCreate.model_validate(valid_data).password == "Password1"
    assert UserLogin.model_validate({"username": "validdependenciesschema", "password": "Password1"}).username == "validdependenciesschema"

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
        "first_name": "Dependency",
        "last_name": "User",
        "email": f"dependency_user_{suffix}@example.com",
        "username": f"dependency_user_{suffix}",
        "password": password,
    }

    user = User.register(db_session, user_data)
    db_session.commit()
    db_session.refresh(user)

    assert repr(user) == f"<User(name=Dependency User, email={user.email})>"
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
        "username": f"dependency_duplicate_{suffix}",
        "password": "Password1",
    }
    with pytest.raises(ValueError, match="already exists"):
        User.register(db_session, duplicate_data)

    invalid_schema_data = user_data | {
        "email": "not-an-email",
        "username": f"dependency_invalid_{suffix}",
        "password": "Password1",
    }
    with pytest.raises(ValueError):
        User.register(db_session, invalid_schema_data)
