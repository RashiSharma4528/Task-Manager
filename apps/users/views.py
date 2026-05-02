from __future__ import annotations

import logging
from typing import Any, cast

from django.contrib.auth import login, logout
from django.core.exceptions import ValidationError
from rest_framework import status
#from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit
from drf_spectacular.utils import extend_schema

from .serializers import LoginSerializer, RegisterSerializer
from .services import AuthService

logger = logging.getLogger(__name__)

# CHANGE 1: BACKEND constant add kiya
BACKEND = "apps.users.auth_backends.EmailAuthBackend"

# ── Register ───────────────────────────────────────────────────
class RegisterView(APIView):  # CHANGE 3: Mixin hata diya
    permission_classes = [AllowAny]

    @extend_schema(
        request=RegisterSerializer,
        responses={201: RegisterSerializer},
        summary="Register a new user",
        tags=["Auth"],
    )
    def post(self, request: Request) -> Response:

        # CHANGE 4: already logged in check seedha post() mein
        if request.user.is_authenticated:
            return Response(
                {"detail": "You are already logged in."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = AuthService.register_user(request.data)

            # CHANGE 5: backend= explicitly pass kiya
            login(request._request, user, backend=BACKEND)

            logger.info("New user registered: %s", user.username)
            return Response(
                {
                    "message": "Welcome! Your account has been created.",
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                    },
                },
                status=status.HTTP_201_CREATED,
            )

        except ValidationError as exc:
            logger.warning(
                "Registration failed for email=%s - %s",
                cast(dict, request.data).get("email"),
                exc,
            )
            return Response(
                {"errors": exc.message_dict if hasattr(exc, "message_dict") else {"detail": exc.messages}},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ── Login ──────────────────────────────────────────────────────
@method_decorator(
    ratelimit(key="ip", rate="5/m", method="POST", block=True),
    name="dispatch",
)
class LoginView(APIView):  # CHANGE 6: Mixin hata diya
    permission_classes = [AllowAny]

    @extend_schema(
        request=LoginSerializer,
        responses={200: LoginSerializer},
        summary="Login with email and password",
        tags=["Auth"],
    )
    def post(self, request: Request) -> Response:

        # CHANGE 7: already logged in check seedha post() mein
        if request.user.is_authenticated:
            return Response(
                {"detail": "You are already logged in."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = AuthService.login_user(request.data)

            # CHANGE 8: backend= explicitly pass kiya
            login(request._request, user, backend=BACKEND)

            logger.info("Successful login: %s", user.email)

            next_url = _safe_next(request)
            return Response(
                {
                    "message": f"Welcome back, {user.username}!",
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                    },
                    "next": next_url,
                },
                status=status.HTTP_200_OK,
            )

        except ValidationError as exc:
            logger.warning(
                "Failed login attempt for email=%s",
                cast(dict, request.data).get("email"),
            )
            return Response(
                {"errors": {"detail": exc.messages}},
                status=status.HTTP_401_UNAUTHORIZED,
            )


# ── Logout ─────────────────────────────────────────────────────
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=None,
        responses={200: None},
        summary="Logout current user",
        tags=["Auth"],
    )
    def post(self, request: Request) -> Response:
        username = request.user.username

        # try:
        #     Token.objects.get(user=request.user).delete()
        # except Token.DoesNotExist:
        #     pass

        # CHANGE 9: logout mein _request use kiya
        logout(request._request)

        logger.info("User logged out: %s", username)
        return Response(
            {"message": "You've been logged out."},
            status=status.HTTP_200_OK,
        )


# ── Safe Redirect ──────────────────────────────────────────────
def _safe_next(request: Request, fallback: str = "dashboard") -> str:
    from urllib.parse import urlparse

    next_url = request.query_params.get("next", "")
    parsed = urlparse(next_url)

    if parsed.scheme or parsed.netloc:
        logger.warning("Rejected unsafe `next` redirect: %s", next_url)
        return fallback

    return next_url or fallback