from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password, make_password
from .models import User
from datetime import timedelta
from django.utils.timezone import now
import uuid
import jwt
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail
from .serializers import (
    RegisterSerializer, LoginSerializer, ChangePasswordSerializer, 
    ForgotPasswordSerializer, ResetPasswordSerializer
)


# JWT Utility
def generate_jwt(user):
    payload = {'user_id': user.userId, 'email': user.email}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

            # Check if the password matches
            if not check_password(password, user.password):
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

            # Ensure user is active
            if not user.is_active:
                return Response({"error": "Email not verified."}, status=status.HTTP_403_FORBIDDEN)

            # Generate JWT token
            token = generate_jwt(user)
            return Response({"token": token}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if check_password(serializer.validated_data['old_password'], user.password):
                user.password = make_password(serializer.validated_data['new_password'])
                user.save()
                return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
            return Response({"error": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    




class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"error": "No user found with this email address."}, status=status.HTTP_404_NOT_FOUND)

            # Generate a UUID token
            reset_token = str(uuid.uuid4())
            user.reset_password_token = reset_token
            user.reset_token_created_at = now()
            user.save()

            # Create the reset password link
            reset_url = f"http://your-frontend-url.com/reset-password?token={reset_token}"

            # Simulate sending email
            subject = "Password Reset Request"
            message = f"Hi {user.name},\n\nYou requested a password reset. Click the link below to reset your password:\n\n{reset_url}\n\nIf you did not request this, please ignore this email."
            from_email = "no-reply@yourdomain.com"
            recipient_list = [email]

            send_mail(subject, message, from_email, recipient_list)

            return Response({"message": "Password reset link sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            try:
                # Find user with the given reset token
                user = User.objects.get(reset_password_token=token)

                # Check token validity (e.g., expire after 1 hour)
                token_age = now() - user.reset_token_created_at
                if token_age > timedelta(hours=1):
                    return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

                # Reset the password
                user.password = make_password(new_password)
                user.reset_password_token = None  # Clear the token
                user.reset_token_created_at = None
                user.save()

                return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CheckStatusView(APIView):
    def get(self, request):
        user = request.user
        return Response({"user": {"id": user.userId, "name": user.name, "email": user.email}}, status=status.HTTP_200_OK)

class SignoutView(APIView):
    def post(self, request):
        # Implement signout logic (if using token blacklist or other session tracking)
        return Response({"message": "Successfully signed out."}, status=status.HTTP_200_OK)
