from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['userId', 'name', 'email', 'role', 'phone', 'address', 'createdAt', 'updatedAt', 'is_active']

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(name=email, password=password)
        if user and user.is_active and user.role == 'admin':
            return user
        raise serializers.ValidationError("Invalid credentials or not an admin user")
    

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('name', 'email', 'password', 'password2', 'role')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    # def create(self, validated_data):
    #     user = User.objects.create(
    #         name=validated_data['name'],
    #         email=validated_data['email'],
    #         role=validated_data['role']
    #     )
    #     user.set_password(validated_data['password'])
    #     user.save()
    #     return user
    def create(self, validated_data):
        # Remove password2 from validated_data
        validated_data.pop('password2', None)
        
        # Create user using create_user method
        user = User.objects.create_user(
            username=validated_data['email'],  # Set username to email
            email=validated_data['email'],
            name=validated_data['name'],
            role=validated_data['role'],
            password=validated_data['password'],  # create_user handles password hashing
            # is_active=False 
        )
        
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(name=email, password=password)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid credentials")

class VerifyEmailSerializer(serializers.Serializer):
    verificationToken = serializers.CharField()

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    resetPasswordToken = serializers.CharField()
    newPassword = serializers.CharField(write_only=True, required=True, validators=[validate_password])

class TwoFactorAuthSerializer(serializers.Serializer):
    twoFactorToken = serializers.CharField()