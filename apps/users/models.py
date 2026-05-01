from __future__ import annotations

import logging
import uuid

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Role Choices
# ─────────────────────────────────────────────

class UserRole(models.TextChoices):
    ADMIN   = "admin",   _("Admin")
    MANAGER = "manager", _("Manager")
    MEMBER  = "member",  _("Member")


# ─────────────────────────────────────────────
# Custom Manager
# ─────────────────────────────────────────────

class UserManager(BaseUserManager):

    def create_user(
        self,
        email: str,
        password: str | None = None,
        **extra_fields,
    ) -> "User":

        if not email:
            raise ValueError("Email is required.")

        email = self.normalize_email(email)

        # Auto-generate username if not provided
        if not extra_fields.get("username"):
            extra_fields["username"] = f"usr_{uuid.uuid4().hex[:8]}"

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        logger.info("User created: email=%s", email)

        return user

    def create_superuser(
        self,
        email: str,
        password: str | None = None,
        **extra_fields,
    ) -> "User":

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", UserRole.ADMIN)
        extra_fields.setdefault("is_active", True)

        #validation - user input wrong
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)

    # Shortcut querysets
    def active(self):
        return self.get_queryset().filter(is_active=True)

    def by_role(self, role: str):
        return self.active().filter(role=role)

    def admins(self):
        return self.by_role(UserRole.ADMIN)

    def managers(self):
        return self.by_role(UserRole.MANAGER)

    def members(self):
        return self.by_role(UserRole.MEMBER)


# ─────────────────────────────────────────────
# Custom User Model
# ─────────────────────────────────────────────

class User(AbstractUser):

    objects = UserManager() # type: ignore

    email = models.EmailField(
        _("email address"),
        unique=True,
        db_index=True,
        error_messages={
            "unique": _("An account with this email already exists."),
        },
    )

    username = models.CharField(
        _("username"),
        max_length=150,
        unique=True,
        blank=True,
        help_text=_("Auto-generated if not provided."),
        error_messages={
            "unique": _("This username is already taken."),
        },
    )

    role = models.CharField(
        max_length=20,
        choices=UserRole.choices,
        default=UserRole.MEMBER,
        db_index=True,
    )

    bio = models.TextField(blank=True, default="")

    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD  = "email"
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name        = _("User")
        verbose_name_plural = _("Users")
        ordering            = ["-date_joined"]
        indexes = [
            models.Index(fields=["role", "is_active"], name="idx_user_role_active"),
            models.Index(fields=["email"],             name="idx_user_email"),
        ]

    def __str__(self) -> str:
        return f"{self.get_full_name() or self.username} <{self.email}>"

    # ─────────────────────────────────────────
    # Role properties
    # ─────────────────────────────────────────

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN or self.is_superuser

    @property
    def is_manager(self) -> bool:
        return self.role == UserRole.MANAGER

    @property
    def is_member(self) -> bool:
        return self.role == UserRole.MEMBER

    @property
    def can_manage_tasks(self) -> bool:
        return self.role in (UserRole.ADMIN, UserRole.MANAGER) or self.is_superuser

    @property
    def full_name(self) -> str:
        name = self.get_full_name().strip()
        return name if name else self.email.split("@")[0]

    # ─────────────────────────────────────────
    # Helper methods
    # ─────────────────────────────────────────

    def get_role_badge(self) -> dict:
        badge_map: dict[str, dict[str, str]] = {
            UserRole.ADMIN:   {"label": "Admin",   "color": "danger"},
            UserRole.MANAGER: {"label": "Manager", "color": "warning"},
            UserRole.MEMBER:  {"label": "Member",  "color": "info"},
        }
        return badge_map.get(self.role, {"label": "Unknown", "color": "secondary"})

    def deactivate(self) -> None:
        self.is_active = False
        self.save(update_fields=["is_active", "updated_at"])
        logger.info("User deactivated: %s", self.email)