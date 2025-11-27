"""
Authentication System for Mobile Analyzer
JWT-based authentication with user registration, login, and role-based access control
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
from enum import Enum

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, validator
import jwt

from models.database import get_db_connection

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Security
security = HTTPBearer(auto_error=False)


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TokenData(BaseModel):
    user_id: int
    username: str
    email: str
    role: UserRole
    exp: datetime


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=4, max_length=128)
    role: UserRole = UserRole.ANALYST

    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (with _ and - allowed)')
        return v

    @validator('password')
    def password_strength(cls, v):
        if len(v) < 4:
            raise ValueError('Password must be at least 4 characters')
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=4, max_length=128)

    @validator('new_password')
    def password_strength(cls, v):
        if len(v) < 4:
            raise ValueError('Password must be at least 4 characters')
        return v


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash password using SHA-256 with salt"""
    if salt is None:
        salt = secrets.token_hex(32)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hashed.hex(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify password against hash"""
    new_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(new_hash, hashed)


def create_access_token(user_data: dict) -> str:
    """Create JWT access token"""
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "email": user_data["email"],
        "role": user_data["role"],
        "exp": expire,
        "type": "access"
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_data: dict) -> str:
    """Create JWT refresh token"""
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "type": "refresh",
        "exp": expire
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Optional[dict]:
    """Get current user from JWT token"""
    if credentials is None:
        return None

    token = credentials.credentials
    payload = decode_token(token)

    if payload is None or payload.get("type") != "access":
        return None

    # Verify user still exists and is active
    async with get_db_connection() as db:
        cursor = await db.execute(
            "SELECT id, username, email, role, is_active FROM users WHERE id = ?",
            (payload["user_id"],)
        )
        user = await cursor.fetchone()

        if not user or not user["is_active"]:
            return None

        return dict(user)


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Require authenticated user"""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await get_current_user(credentials)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(allowed_roles: List[UserRole]):
    """Dependency factory for role-based access control"""
    async def role_checker(user: dict = Depends(require_auth)) -> dict:
        if UserRole(user["role"]) not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {[r.value for r in allowed_roles]}"
            )
        return user
    return role_checker


# Role shortcuts
require_admin = require_role([UserRole.ADMIN])
require_analyst = require_role([UserRole.ADMIN, UserRole.ANALYST])
require_viewer = require_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])


class UserRepository:
    """Repository for user operations"""

    @staticmethod
    async def init_table():
        """Initialize users table"""
        async with get_db_connection() as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    role TEXT DEFAULT 'analyst',
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            """)

            # Create audit log table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)
            """)

            await db.commit()

    @staticmethod
    async def create(user_data: UserCreate) -> int:
        """Create a new user"""
        password_hash, password_salt = hash_password(user_data.password)

        async with get_db_connection() as db:
            # Check if username or email already exists
            cursor = await db.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (user_data.username, user_data.email)
            )
            if await cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username or email already registered"
                )

            cursor = await db.execute("""
                INSERT INTO users (username, email, password_hash, password_salt, role)
                VALUES (?, ?, ?, ?, ?)
            """, (
                user_data.username,
                user_data.email,
                password_hash,
                password_salt,
                user_data.role.value
            ))
            await db.commit()
            return cursor.lastrowid

    @staticmethod
    async def authenticate(username: str, password: str) -> Optional[dict]:
        """Authenticate user and return user data if valid"""
        async with get_db_connection() as db:
            cursor = await db.execute("""
                SELECT id, username, email, password_hash, password_salt, role,
                       is_active, created_at, last_login, failed_login_attempts, locked_until
                FROM users WHERE username = ? OR email = ?
            """, (username, username))
            user = await cursor.fetchone()

            if not user:
                return None

            user = dict(user)

            # Check if account is locked
            if user.get("locked_until"):
                locked_until = datetime.fromisoformat(user["locked_until"])
                if locked_until > datetime.utcnow():
                    raise HTTPException(
                        status_code=status.HTTP_423_LOCKED,
                        detail=f"Account locked until {locked_until.isoformat()}"
                    )
                else:
                    # Unlock account
                    await db.execute(
                        "UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?",
                        (user["id"],)
                    )
                    await db.commit()

            if not user["is_active"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is disabled"
                )

            if not verify_password(password, user["password_hash"], user["password_salt"]):
                # Increment failed attempts
                failed_attempts = user.get("failed_login_attempts", 0) + 1
                locked_until = None

                if failed_attempts >= 5:
                    locked_until = datetime.utcnow() + timedelta(minutes=15)

                await db.execute("""
                    UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?
                """, (failed_attempts, locked_until.isoformat() if locked_until else None, user["id"]))
                await db.commit()

                return None

            # Reset failed attempts and update last login
            await db.execute("""
                UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?
            """, (user["id"],))
            await db.commit()

            return {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "is_active": user["is_active"],
                "created_at": user["created_at"],
                "last_login": datetime.utcnow().isoformat()
            }

    @staticmethod
    async def get_by_id(user_id: int) -> Optional[dict]:
        """Get user by ID"""
        async with get_db_connection() as db:
            cursor = await db.execute("""
                SELECT id, username, email, role, is_active, created_at, last_login
                FROM users WHERE id = ?
            """, (user_id,))
            user = await cursor.fetchone()
            return dict(user) if user else None

    @staticmethod
    async def get_all(limit: int = 100, offset: int = 0) -> List[dict]:
        """Get all users"""
        async with get_db_connection() as db:
            cursor = await db.execute("""
                SELECT id, username, email, role, is_active, created_at, last_login
                FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    @staticmethod
    async def update_role(user_id: int, role: UserRole) -> bool:
        """Update user role"""
        async with get_db_connection() as db:
            await db.execute(
                "UPDATE users SET role = ? WHERE id = ?",
                (role.value, user_id)
            )
            await db.commit()
            return True

    @staticmethod
    async def update_password(user_id: int, new_password: str) -> bool:
        """Update user password"""
        password_hash, password_salt = hash_password(new_password)
        async with get_db_connection() as db:
            await db.execute("""
                UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?
            """, (password_hash, password_salt, user_id))
            await db.commit()
            return True

    @staticmethod
    async def toggle_active(user_id: int) -> bool:
        """Toggle user active status"""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT is_active FROM users WHERE id = ?", (user_id,)
            )
            user = await cursor.fetchone()
            if not user:
                return False

            new_status = not user["is_active"]
            await db.execute(
                "UPDATE users SET is_active = ? WHERE id = ?",
                (new_status, user_id)
            )
            await db.commit()
            return new_status

    @staticmethod
    async def verify_password(user_id: int, password: str) -> bool:
        """Verify user's current password"""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT password_hash, password_salt FROM users WHERE id = ?",
                (user_id,)
            )
            user = await cursor.fetchone()
            if not user:
                return False
            return verify_password(password, user["password_hash"], user["password_salt"])

    @staticmethod
    async def count() -> int:
        """Get total user count"""
        async with get_db_connection() as db:
            cursor = await db.execute("SELECT COUNT(*) as count FROM users")
            row = await cursor.fetchone()
            return row["count"] if row else 0


class AuditLog:
    """Audit logging for security events"""

    @staticmethod
    async def log(
        action: str,
        user_id: Optional[int] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        details: Optional[str] = None,
        request: Optional[Request] = None
    ):
        """Log an audit event"""
        ip_address = None
        user_agent = None

        if request:
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")

        async with get_db_connection() as db:
            await db.execute("""
                INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, action, resource_type, resource_id, details, ip_address, user_agent))
            await db.commit()

    @staticmethod
    async def get_logs(
        user_id: Optional[int] = None,
        action: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[dict]:
        """Get audit logs with optional filters"""
        async with get_db_connection() as db:
            conditions = []
            params = []

            if user_id:
                conditions.append("user_id = ?")
                params.append(user_id)

            if action:
                conditions.append("action = ?")
                params.append(action)

            where_clause = " AND ".join(conditions) if conditions else "1=1"

            cursor = await db.execute(f"""
                SELECT al.*, u.username
                FROM audit_log al
                LEFT JOIN users u ON al.user_id = u.id
                WHERE {where_clause}
                ORDER BY al.created_at DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
