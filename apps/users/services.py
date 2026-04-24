from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction

User = get_user_model()

class AuthService:

    # Register User
    @staticmethod
    @transaction.atomic

    def register_user(data):
        username = (data.get("username") or "").strip()
        email = (data.get("email")or"").strip().lower()
        password = data.get("password")
        full_name = (data.get("full_name") or "").strip()

        if not username:
            raise ValidationError({"username" : "Username is required."})
        if not email:
            raise ValidationError({"email" : "Email is required"})
        if not password:
            raise ValidationError({"password" : "Password is required"})
        
        # password validation
        validate_password(password)

        # Uniqueness check
        if User.objects.filter(username=username).exists():
            raise ValidationError({"username":"Username is already exists"})
        if User.objects.filter(email=email).exists():
            raise ValidationError({"email":"Email is already registered"})
        
        #Creating user

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )

        #Handle full name
        if hasattr(user, "full_name"):
             parts = full_name.split("",1)
             user.first_name = parts[0] if parts else ""
             user.last_name = parts[1] if len(parts)>1 else""
             user.save(update_fields = ["first_name","last_name"])

        return user
    
    # Login User
    @staticmethod
    def login_user(data):
        email = (data.get("email") or "").strip().lower()
        password = (data.get("password"))

        if not email or password:
            raise ValidationError("Login Credential is required")
        
        #Authenticate directly via email
        user = authenticate(email=email, password=password)

        if user is None:
            raise ValidationError("Invalid email or password")
        
        if not user.is_active:
            raise ValidationError("Account is disabled")
        
        return user
    
    # Logout User
    @staticmethod
    def logout_user():
        return True