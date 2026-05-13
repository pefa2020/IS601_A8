# tests/integration/test_user_auth.py

import pytest
from uuid import UUID
import pydantic_core
from sqlalchemy.exc import IntegrityError
from app.models.user import User

def test_password_hashing(db_session, fake_user_data):
    """Test password hashing and verification functionality"""
    original_password = "TestPass123"  # Use known password for test
    hashed = User.hash_password(original_password)
    
    user = User(
        first_name=fake_user_data['first_name'],
        last_name=fake_user_data['last_name'],
        email=fake_user_data['email'],
        username=fake_user_data['username'],
        password=hashed
    )
    
    assert user.verify_password(original_password) is True
    assert user.verify_password("WrongPass123") is False
    assert hashed != original_password

def test_user_registration(db_session, fake_user_data):
    """Test user registration process"""
    fake_user_data['password'] = "TestPass123"
    
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.first_name == fake_user_data['first_name']
    assert user.last_name == fake_user_data['last_name']
    assert user.email == fake_user_data['email']
    assert user.username == fake_user_data['username']
    assert user.is_active is True
    assert user.is_verified is False
    assert user.verify_password("TestPass123") is True

def test_duplicate_user_registration(db_session):
    """Test registration with duplicate email/username"""
    # First user data
    user1_data = {
        "first_name": "Test",
        "last_name": "User1",
        "email": "unique.test@example.com",
        "username": "uniqueuser1",
        "password": "TestPass123"
    }
    
    # Second user data with same email
    user2_data = {
        "first_name": "Test",
        "last_name": "User2",
        "email": "unique.test@example.com",  # Same email
        "username": "uniqueuser2",
        "password": "TestPass123"
    }
    
    # Register first user
    first_user = User.register(db_session, user1_data)
    db_session.commit()
    db_session.refresh(first_user)
    
    # Try to register second user with same email
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user2_data)

def test_user_authentication(db_session, fake_user_data):
    """Test user authentication and token generation"""
    # Use fake_user_data from fixture
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Test successful authentication
    auth_result = User.authenticate(
        db_session,
        fake_user_data['username'],
        "TestPass123"
    )
    
    assert auth_result is not None
    assert "access_token" in auth_result
    assert "token_type" in auth_result
    assert auth_result["token_type"] == "bearer"
    assert "user" in auth_result

def test_user_last_login_update(db_session, fake_user_data):
    """Test that last_login is updated on authentication"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Authenticate and check last_login
    assert user.last_login is None
    auth_result = User.authenticate(db_session, fake_user_data['username'], "TestPass123")
    db_session.refresh(user)
    assert user.last_login is not None

def test_unique_email_username(db_session):
    """Test uniqueness constraints for email and username"""
    # Create first user with specific test data
    user1_data = {
        "first_name": "Test",
        "last_name": "User1",
        "email": "unique_test@example.com",
        "username": "uniqueuser",
        "password": "TestPass123"
    }
    
    # Register and commit first user
    User.register(db_session, user1_data)
    db_session.commit()
    
    # Try to create user with same email
    user2_data = {
        "first_name": "Test",
        "last_name": "User2",
        "email": "unique_test@example.com",  # Same email
        "username": "differentuser",
        "password": "TestPass123"
    }
    
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user2_data)

def test_short_password_registration(db_session):
    """Test that registration fails with a short password"""
    # Prepare test data with a 5-character password
    test_data = {
        "first_name": "Password",
        "last_name": "Test",
        "email": "short.pass@example.com",
        "username": "shortpass",
        "password": "Shor1"  # 5 characters, should fail
    }
    
    # Attempt registration with short password
    with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
        User.register(db_session, test_data)

def test_invalid_token():
    """Test that invalid tokens are rejected"""
    invalid_token = "invalid.token.string"
    result = User.verify_token(invalid_token)
    assert result is None

def test_token_creation_and_verification(db_session, fake_user_data):
    """Test token creation and verification"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Create token
    token = User.create_access_token({"sub": str(user.id)})
    
    # Verify token
    decoded_user_id = User.verify_token(token)
    assert decoded_user_id == user.id

def test_authenticate_with_email(db_session, fake_user_data):
    """Test authentication using email instead of username"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Test authentication with email
    auth_result = User.authenticate(
        db_session,
        fake_user_data['email'],  # Using email instead of username
        "TestPass123"
    )
    
    assert auth_result is not None
    assert "access_token" in auth_result

def test_user_model_representation(test_user):
    """Test the string representation of User model"""
    expected = f"<User(name={test_user.first_name} {test_user.last_name}, email={test_user.email})>"
    assert str(test_user) == expected

def test_missing_password_registration(db_session):
    """Test that registration fails when no password is provided."""
    test_data = {
        "first_name": "NoPassword",
        "last_name": "Test",
        "email": "no.password@example.com",
        "username": "nopassworduser",
        # Password is missing
    }
    
    # Adjust the expected error message
    with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
        User.register(db_session, test_data)


def test_user_auth_command_covers_application_helpers(db_session, monkeypatch):
    """Exercise app branches included in the global coverage report."""
    import uuid
    from unittest.mock import patch

    from fastapi import HTTPException
    from sqlalchemy.exc import SQLAlchemyError

    import app.database as database
    import app.database_init as database_init
    from app.auth.dependencies import get_current_active_user, get_current_user
    from app.operations import add, divide, multiply, subtract
    from app.schemas.base import PasswordMixin, UserCreate, UserLogin
    from app.schemas.user import UserResponse

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
        "email": "valid_user_auth_schema@example.com",
        "username": "validuserauthschema",
        "password": "Password1",
    }
    assert UserCreate.model_validate(valid_data).password == "Password1"
    assert UserLogin.model_validate({"username": "validuserauthschema", "password": "Password1"}).username == "validuserauthschema"

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
        "last_name": "Dependency",
        "email": f"user_auth_dependency_{suffix}@example.com",
        "username": f"user_auth_dependency_{suffix}",
        "password": password,
    }
    user = User.register(db_session, user_data)
    db_session.commit()
    db_session.refresh(user)

    token = User.create_access_token({"sub": str(user.id)})
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
