from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['userId', 'name', 'email', 'role', 'phone', 'address']
        extra_kwargs = {
            'email': {'required': True},
            'name': {'required': True},
            'role': {'required': True},
        }

class RegisterSerializer(serializers.ModelSerializer):
    passwordHash = serializers.CharField(max_length=255, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'passwordHash', 'role', 'phone', 'address']
        extra_kwargs = {
            'email': {'required': True},
            'name': {'required': True},
            'passwordHash': {'required': True},
            'role': {'required': True},
        }

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    passwordHash = serializers.CharField(max_length=255, write_only=True)

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255, required=True)
    passwordHash = serializers.CharField(max_length=255, write_only=True)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=255, write_only=True)
    new_password = serializers.CharField(max_length=255, write_only=True)