from __future__ import annotations

from rest_framework import serializers


class RegisterSerializer(serializers.Serializer):
    email     = serializers.EmailField()
    password  = serializers.CharField(write_only=True)
    full_name = serializers.CharField(required=False, default="")


class LoginSerializer(serializers.Serializer):
    email    = serializers.EmailField()
    password = serializers.CharField(write_only=True)