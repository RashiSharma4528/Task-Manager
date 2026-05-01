from __future__ import annotations

import logging
from typing import Any, cast

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.decorators import method_decorator
from django.views import View
from django_ratelimit.decorators import ratelimit

from .services import AuthService

logger = logging.getLogger(__name__)


# ── Mixin — Block authenticates users ───────────────────────────────────
class RedirectAuthenticatedMixin:
    redirect_authenticated_to: str = "dashboard"

    def dispatch(self, request: Request, *args: Any, **kwargs: Any) -> Response:  # type: ignore[no-untyped-def]
        if request.user.is_authenticated:
            return Response(
                {"detail": "You are already logged in."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]


# ── Register ───────────────────────────────────────────────────────────────────
class RegisterView(RedirectAuthenticatedMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        try:
            user = AuthService.register_user(request.data)  # request.POST → request.data
            login(request._request, user)  # type: ignore[arg-type]

            logger.info("New user registered: %s", user.username)
            return Response(
                {
                    "message": "Welcome! Your account has been created.",
                    "user": {
                        "id": user.id, # type: ignore
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


# ── Login ──────────────────────────────────────────────────────────────────────
@method_decorator(
    ratelimit(key="ip", rate="5/m", method="POST", block=True),
    name="dispatch",
)
class LoginView(RedirectAuthenticatedMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        try:
            user = AuthService.login_user(request.data)  # request.POST → request.data
            login(request._request, user)  # type: ignore[arg-type]

            logger.info("Successful login: %s", user.email)

            next_url = _safe_next(request)  # purana function same hai
            return Response(
                {
                    "message": f"Welcome back, {user.username}!",
                    "user": {
                        "id": user.id, # type: ignore
                        "username": user.username,
                        "email": user.email,
                    },
                    "next": next_url,  # frontend khud redirect karega
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


# ── Logout ─────────────────────────────────────────────────────────────────────
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # LoginRequiredMixin → IsAuthenticated

    def post(self, request: Request) -> Response:
        username = request.user.username
        
        # Delete token for REST Framework auth
        try:
            Token.objects.get(user=request.user).delete() # current user ka token delete.
        except Token.DoesNotExist:
            pass

        logger.info("User logged out: %s", username)
        return Response(
            {"message": "You've been logged out."},
            status=status.HTTP_200_OK,
        )


# ── Safe Redirect — bilkul same, sirf next_url frontend ko bhej rahe hain ──────
def _safe_next(request: Request, fallback: str = "dashboard") -> str:
    from urllib.parse import urlparse

    next_url = request.query_params.get("next", "")
    parsed = urlparse(next_url)

    if parsed.scheme or parsed.netloc:
        logger.warning("Rejected unsafe `next` redirect: %s", next_url)
        return fallback

    return next_url or fallback