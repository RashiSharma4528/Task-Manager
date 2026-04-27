from __future__ import annotations
 
import logging
import uuid
 
from django.contrib.auth.models import AbstractUser, BaseUserManager, User
from django.db import models
from django.utils.translation import gettext_lazy as _
 
logger = logging.getLogger(__name__)

# Role choices

class UserRole(models.TextChoices):

    ADMIN = "admin", _("Admin")
    MANAGER = "manager", _("Manager")
    MEMBER = "member", _("Member")

# Custom Manager

class UserManager(BaseUserManager):
    def create_user(self, email:str, password:str | None = None, **extra_fields,) -> "User":
        if not email:
            raise ValueError(_("Email address is required"))
        
        # Normalize email = Rashi@gmail.com to rashi@gmail.com
        email = self.normalize_email(email)

        if "username" not in extra_fields or not extra_fields["username"]:
            extra_fields["username"] = f"usr_{uuid.uuid4().hex[:8]}"

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        logger.info("User created: email=%s", email)

        return user
    
    def create_superuser(self, email:str, password:str | None=None, **extra_fields,) -> "User":
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser",True)
        extra_fields.setdefault("role",UserRole.ADMIN)
        extra_fields.setdefault("is_active",True)

        #validation - user input wrong
        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        
        return self.create_user(email, password, **extra_fields)