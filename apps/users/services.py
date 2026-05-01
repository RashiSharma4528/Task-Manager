from typing import TYPE_CHECKING

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from rest_framework.exceptions import ValidationError

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser
    User = AbstractUser
else:
    User = get_user_model()


class AuthService:

    # ─────────────────────────────────────────────
    # Register User
    # ─────────────────────────────────────────────
    @staticmethod
    @transaction.atomic
    def register_user(data) -> "User":

        # Clean input data
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password")
        full_name = (data.get("full_name") or "").strip()

        # Required field validation
        if not username:
            raise ValidationError({
                "username": ["Username is required."]
            })

        if not email:
            raise ValidationError({
                "email": ["Email is required."]
            })

        if not password:
            raise ValidationError({
                "password": ["Password is required."]
            })

        # Password validation
        try:
            validate_password(password)

        except Exception as exc:
            raise ValidationError({
                "password": [str(exc)]
            })

        # Username uniqueness check
        if User.objects.filter(username=username).exists():
            raise ValidationError({
                "username": ["Username already exists."]
            })

        # Email uniqueness check
        if User.objects.filter(email=email).exists():
            raise ValidationError({
                "email": ["Email already registered."]
            })

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )

        # Handle full name
        if full_name:

            parts = full_name.split(" ", 1)

            user.first_name = parts[0]
            user.last_name = parts[1] if len(parts) > 1 else ""

            user.save(update_fields=["first_name", "last_name"])

        return user

    # ─────────────────────────────────────────────
    # Login User
    # ─────────────────────────────────────────────
    @staticmethod
    def login_user(data) -> "User":

        # Clean input data
        email = (data.get("email") or "").strip().lower()
        password = data.get("password")

        # Required field validation
        if not email or not password:
            raise ValidationError({
                "detail": ["Email and password are required."]
            })

        # Authenticate user
        user = authenticate(
            email=email,
            password=password,
        )

        # Invalid credentials
        if user is None:
            raise ValidationError({
                "detail": ["Invalid email or password."]
            })

        # Disabled account
        if not user.is_active:
            raise ValidationError({
                "detail": ["Account is disabled."]
            })

        return user
    
    # Logout User
    @staticmethod
    def logout_user():
        return True