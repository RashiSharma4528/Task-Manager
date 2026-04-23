from __future__ import annotations

import logging
from typing import Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views import View
from django_ratelimit.decorators import ratelimit  # pip install django-ratelimit

from .services import AuthService

logger = logging.getLogger(__name__)

class RedirectAuthenticatedMixin:
    redirect_authenticated_to :str = "dashboard"

    def dispatch(self, HttpRequest, *args:Any, **kwargs:Any) -> HttpResponse:
        if request.user.is_authenticated:
            return redirect(self.redirect_authenticated_to)
        return super().dispatch(request, *args, **kwargs)
    
class RegisterView(RedirectAuthenticatedMixin, View):
    template_name = "register.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        return render(request, self.template_name)
    
    def post(self, request: HttpRequest) -> HttpResponse:
        try:
            AuthService.register_user(request.POST, request)
            logger.info("New user registered: %s", request.POST.get("username"))
            messages.success(request, "Welcome! Your account has been created.")
            return redirect("dashboard")
        except ValidationError as exc:
            logger.warning(
                "Registration failed for email=%s - %s",
                request.POST.get("email"),
                exc.message,
            )
            messages.error(request, str(exc.message))
            return render(
                request, self.template_name,
                {
                    "form_data" : {
                        "email": request.POST.get("email", ""),
                        "username" : request.POST.get("username", ""),
                        "full_name": request.POST.get("full_name","")
                    }
                },
                status=400,
            )
        
@method_decorator(
    ratelimit(key="ip", rate="5/m", method="POST", block=True),
    name = "dispatch",
)

class LoginView(RedirectAuthenticatedMixin, View):
    template_name = "login.html"

    def get(self, request:HttpRequest) -> HttpResponse:
        return render(request, self.template_name)
    def post(self, request:HttpRequest) -> HttpResponse:
        try:
            AuthService.login_user(request.POST, request)
            logger.info("Successful login: %s", request.POST.get("email"))
            messages.success(request, f"Welcome back, {request.user.username}!")

            next_url = _safe_next(request)
            return redirect(next_url)
        except ValidationError as exc:
            logger.warning(
                "Failed login attempt for email=%s",
                request.POST.get("email"),
            )
            messages.error(request, str(exc.message))
            return render(
                request,
                self.template_name,
                {"form_data":{"email":request.POST.get("email","")}},
                status = 400,
            )

class LogoutView(LoginRequiredMixin, view):
    login_url = "/login/"

    def post(self, request:HttpRequest) -> HttpResponse:
        username = request.user.username
        AuthService.logout_user(request)
        logger.info("User logged out: %s", username)
        messages.info(request, "You've been logged out.")
        return redirect("login")
    
class DashboardView(LoginRequiredMixin, View):

    template_name = "dashboard.html"
    login_url = "/login/"

    def get(self, request:HttpRequest)-> HttpResponse:
        return render(request, self.template_name, {"user":request.user})