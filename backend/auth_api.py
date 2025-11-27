"""
Authentication API Routes
Handles user registration, login, token refresh, and user management
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Optional

from auth import (
    UserCreate, UserLogin, UserResponse, TokenResponse, RefreshTokenRequest,
    PasswordChangeRequest, UserRole, UserRepository, AuditLog,
    create_access_token, create_refresh_token, decode_token,
    require_auth, require_admin, require_analyst,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, request: Request):
    """
    Register a new user account.

    First user registered becomes admin automatically.
    """
    # Check if this is the first user (make them admin)
    user_count = await UserRepository.count()
    if user_count == 0:
        user_data.role = UserRole.ADMIN

    user_id = await UserRepository.create(user_data)
    user = await UserRepository.get_by_id(user_id)

    # Log registration
    await AuditLog.log(
        action="user_registered",
        user_id=user_id,
        details=f"User {user_data.username} registered",
        request=request
    )

    # Generate tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user)
    )


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request):
    """
    Authenticate user and return tokens.
    """
    user = await UserRepository.authenticate(credentials.username, credentials.password)

    if not user:
        await AuditLog.log(
            action="login_failed",
            details=f"Failed login attempt for {credentials.username}",
            request=request
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Log successful login
    await AuditLog.log(
        action="user_login",
        user_id=user["id"],
        details=f"User {user['username']} logged in",
        request=request
    )

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user)
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(token_request: RefreshTokenRequest, request: Request):
    """
    Refresh access token using refresh token.
    """
    payload = decode_token(token_request.refresh_token)

    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    user = await UserRepository.get_by_id(payload["user_id"])

    if not user or not user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled"
        )

    access_token = create_access_token(user)
    new_refresh_token = create_refresh_token(user)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user)
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(require_auth)):
    """
    Get current authenticated user info.
    """
    user = await UserRepository.get_by_id(current_user["id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(**user)


@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Change current user's password.
    """
    # Verify current password
    is_valid = await UserRepository.verify_password(
        current_user["id"],
        password_data.current_password
    )

    if not is_valid:
        await AuditLog.log(
            action="password_change_failed",
            user_id=current_user["id"],
            details="Invalid current password",
            request=request
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    await UserRepository.update_password(current_user["id"], password_data.new_password)

    await AuditLog.log(
        action="password_changed",
        user_id=current_user["id"],
        request=request
    )

    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(request: Request, current_user: dict = Depends(require_auth)):
    """
    Logout current user (client should discard tokens).
    """
    await AuditLog.log(
        action="user_logout",
        user_id=current_user["id"],
        request=request
    )
    return {"message": "Logged out successfully"}


# ==================== Admin Routes ====================

@router.get("/users", response_model=List[UserResponse])
async def list_users(
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(require_admin)
):
    """
    List all users (admin only).
    """
    users = await UserRepository.get_all(limit, offset)
    return [UserResponse(**user) for user in users]


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, current_user: dict = Depends(require_admin)):
    """
    Get user by ID (admin only).
    """
    user = await UserRepository.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(**user)


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    role: UserRole,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """
    Update user role (admin only).
    """
    if user_id == current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role"
        )

    user = await UserRepository.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await UserRepository.update_role(user_id, role)

    await AuditLog.log(
        action="user_role_changed",
        user_id=current_user["id"],
        resource_type="user",
        resource_id=user_id,
        details=f"Changed role to {role.value}",
        request=request
    )

    return {"message": f"User role updated to {role.value}"}


@router.post("/users/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: int,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """
    Toggle user active status (admin only).
    """
    if user_id == current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot disable your own account"
        )

    new_status = await UserRepository.toggle_active(user_id)

    await AuditLog.log(
        action="user_status_changed",
        user_id=current_user["id"],
        resource_type="user",
        resource_id=user_id,
        details=f"User {'enabled' if new_status else 'disabled'}",
        request=request
    )

    return {"message": f"User {'enabled' if new_status else 'disabled'}", "is_active": new_status}


@router.get("/audit-logs")
async def get_audit_logs(
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(require_admin)
):
    """
    Get audit logs (admin only).
    """
    logs = await AuditLog.get_logs(user_id, action, limit, offset)
    return {"logs": logs, "count": len(logs)}
