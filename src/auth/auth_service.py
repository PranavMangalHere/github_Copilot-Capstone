"""Authentication service with business logic."""
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

import bcrypt
import jwt
from sqlalchemy.orm import Session

from .models import User, UserRole, PasswordResetToken

# Configuration
JWT_SECRET = "your-secret-key"  # Load from env in production
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24
BCRYPT_ROUNDS = 12
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30
RESET_TOKEN_EXPIRY_HOURS = 1


class AuthService:
    """Handles user authentication and authorization."""

    def __init__(self, db: Session):
        self.db = db

    def register_user(
        self,
        email: str,
        password: str
    ) -> Tuple[bool, str]:
        """
        Register a new user.
        
        Args:
            email: User email address
            password: Plain text password
            
        Returns:
            Tuple of (success, message)
        """
        # Check if email exists
        existing = self.db.query(User).filter(User.email == email).first()
        if existing:
            return False, "Email already registered"
        
        # Validate password complexity
        if not self._validate_password(password):
            return False, "Password must be 8+ chars with upper, lower, number, special char"
        
        # Hash password and create user
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        ).decode("utf-8")
        
        user = User(
            email=email.lower().strip(),
            password_hash=password_hash,
            is_active=True,
            is_email_verified=False,
            role=UserRole.USER
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        return True, str(user.id)

    def login_user(
        self,
        email: str,
        password: str
    ) -> Tuple[bool, str]:
        """
        Authenticate user and return JWT token.
        
        Args:
            email: User email
            password: Plain text password
            
        Returns:
            Tuple of (success, token_or_error_message)
        """
        user = self.db.query(User).filter(
            User.email == email.lower().strip()
        ).first()
        
        if not user:
            return False, "Invalid credentials"
        
        # Check account lock
        if user.is_locked:
            return False, f"Account locked until {user.locked_until.isoformat()}"
        
        # Verify password
        if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
            self._handle_failed_login(user)
            return False, "Invalid credentials"
        
        # Check email verification
        if not user.is_email_verified:
            return False, "Please verify your email before logging in"
        
        # Reset failed attempts on success
        user.failed_login_attempts = 0
        user.locked_until = None
        self.db.commit()
        
        # Generate JWT token
        token = self._generate_jwt(user)
        return True, token

    def request_password_reset(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Request a password reset token.
        
        Args:
            email: User email
            
        Returns:
            Tuple of (success, reset_token_or_None)
        """
        user = self.db.query(User).filter(User.email == email).first()
        
        if not user:
            # Don't reveal if email exists
            return True, None
        
        # Invalidate old tokens
        self.db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used == False
        ).update({"used": True})
        
        # Create new token
        token = secrets.token_urlsafe(32)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=datetime.utcnow() + timedelta(hours=RESET_TOKEN_EXPIRY_HOURS)
        )
        
        self.db.add(reset_token)
        self.db.commit()
        
        return True, token

    def reset_password(self, token: str, new_password: str) -> Tuple[bool, str]:
        """
        Reset user password using a reset token.
        
        Args:
            token: Password reset token
            new_password: New plain text password
            
        Returns:
            Tuple of (success, message)
        """
        reset_token = self.db.query(PasswordResetToken).filter(
            PasswordResetToken.token == token,
            PasswordResetToken.used == False
        ).first()
        
        if not reset_token:
            return False, "Invalid or expired reset token"
        
        if datetime.utcnow() > reset_token.expires_at:
            return False, "Reset token has expired"
        
        # Validate new password
        if not self._validate_password(new_password):
            return False, "Password must be 8+ chars with upper, lower, number, special char"
        
        # Update password and invalidate token
        user = self.db.query(User).filter(User.id == reset_token.user_id).first()
        user.password_hash = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        ).decode("utf-8")
        
        reset_token.used = True
        self.db.commit()
        
        return True, "Password reset successfully"

    def _validate_password(self, password: str) -> bool:
        """Validate password meets complexity requirements."""
        import re
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?":{}|<>]", password):
            return False
        return True

    def _handle_failed_login(self, user: User) -> None:
        """Increment failed attempts and lock account if threshold reached."""
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(
                minutes=LOCKOUT_DURATION_MINUTES
            )
        self.db.commit()

    def _generate_jwt(self, user: User) -> str:
        """Generate JWT token for authenticated user."""
        payload = {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role.value,
            "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
