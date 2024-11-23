from datetime import datetime
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, OTP
from .serializers import UserSerializer, LoginSerializer,RegisterSerializer, OTPVerifySerializer, LoginSerializer, VerifyEmailSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, TwoFactorAuthSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from .utils import email_verification_token
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_str, force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import pyotp
from rest_framework.permissions import AllowAny
from .tokens import email_verification_token
from django.contrib.auth import get_user_model
import random
import string
from django.utils import timezone
    

User = get_user_model()

class UserListView(generics.ListAPIView):
    serializer_class = UserSerializer

    def get_queryset(self):
        queryset = User.objects.all()
        role = self.request.query_params.get('role', None)
        status = self.request.query_params.get('status', None)
        if role:
            queryset = queryset.filter(role=role)
        if status:
            is_active = True if status == 'active' else False
            queryset = queryset.filter(is_active=is_active)
        return queryset

class UserDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'userId'

class UserStatusUpdateView(APIView):
    def put(self, request, userId):
        try:
            user = User.objects.get(userId=userId)
            status = request.data.get('status')
            if status == 'active':
                user.is_active = True
            elif status == 'inactive':
                user.is_active = False
            user.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        

# class LoginView(APIView):
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.validated_data
#             refresh = RefreshToken.for_user(user)
#             return Response({
#                 'refresh': str(refresh),
#                 'access': str(refresh.access_token),
#             })
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            otp_code = generate_otp()
            OTP.objects.create(user=user, otp_code=otp_code)
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({'status': 'OTP sent to your email'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OTPLoginVerifyView(APIView):
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            try:
                user = User.objects.get(email=email)
                otp = OTP.objects.get(user=user, otp_code=otp_code)
                
                if otp.expires_at > timezone.now():
                    # Create token with additional claims
                    refresh = RefreshToken.for_user(user)
                    refresh['email'] = user.email
                    refresh['name'] = user.name
                    refresh['role'] = user.role
                    
                    # Delete the used OTP
                    otp.delete()
                    
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'user': {
                            'userId': user.userId,
                            'email': user.email,
                            'name': user.name,
                            'role': user.role,
                            # 'phone': user.phone,
                        }
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'OTP expired'
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found'
                }, status=status.HTTP_400_BAD_REQUEST)
            except OTP.DoesNotExist:
                return Response({
                    'error': 'Invalid OTP'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class OTPLoginVerifyView(APIView):
#     def post(self, request):
#         serializer = OTPVerifySerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             otp_code = serializer.validated_data['otp_code']
#             try:
#                 user = User.objects.get(email=email)
#                 otp = OTP.objects.get(user=user, otp_code=otp_code)
#                 if otp.expires_at > timezone.now():
#                     refresh = RefreshToken.for_user(user)
#                     otp.delete()
#                     return Response({
#                         'refresh': str(refresh),
#                         'access': str(refresh.access_token),
#                     }, status=status.HTTP_200_OK)
#                 else:
#                     return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
#             except (User.DoesNotExist, OTP.DoesNotExist):
#                 return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class LoginView(APIView):
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.validated_data
#             login(request, user)
#             refresh = RefreshToken.for_user(user)
#             return Response({
#                 'refresh': str(refresh),
#                 'access': str(refresh.access_token),
#             })
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class AdminOnlyView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':
            return Response({'error': 'You do not have permission to access this resource'}, status=status.HTTP_403_FORBIDDEN)
        return Response({'message': 'Welcome, admin!'}, status=status.HTTP_200_OK)
    
# class RegisterView(generics.CreateAPIView):
#     queryset = User.objects.all()
#     serializer_class = RegisterSerializer

def generate_otp(length=6):
    digits = string.digits
    otp = ''.join(random.choices(digits, k=length))
    return otp

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        otp_code = generate_otp()
        OTP.objects.create(user=user, otp_code=otp_code)
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp_code}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

class OTPVerifyView(APIView):
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            try:
                user = User.objects.get(email=email)
                otp = OTP.objects.get(user=user, otp_code=otp_code)
                if otp.expires_at > timezone.now():
                    user.is_active = True
                    user.save()
                    otp.delete()
                    return Response({'status': 'success'}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
            except (User.DoesNotExist, OTP.DoesNotExist):
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class OTPVerifyView(APIView):
#     def post(self, request):
#         serializer = OTPVerifySerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             otp_code = serializer.validated_data['otp_code']
#             try:
#                 user = User.objects.get(email=email)
#                 otp = OTP.objects.get(user=user, otp_code=otp_code)
#                 if otp.expires_at > datetime.now():
#                     user.is_active = True
#                     user.save()
#                     otp.delete()
#                     return Response({'status': 'success'}, status=status.HTTP_200_OK)
#                 else:
#                     return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
#             except (User.DoesNotExist, OTP.DoesNotExist):
#                 return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)

class VerifyEmailView(APIView):
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            token = email_verification_token.make_token(user)
            verification_url = request.build_absolute_uri(
                reverse('verify-email', kwargs={'token': token})
            )
            send_mail(
                'Verify your email',
                f'Click the link to verify your email: {verification_url}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ConfirmEmailView(APIView):
    def get(self, request, token):
        try:
            user_id = force_str(urlsafe_base64_decode(token))
            user = User.objects.get(pk=user_id)
            if email_verification_token.check_token(user, token):
                user.is_active = True
                user.save()
                return Response({'status': 'success'}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)    

class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                token = PasswordResetTokenGenerator().make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_url = request.build_absolute_uri(
                    reverse('reset-password', kwargs={'uidb64': uid, 'token': token})
                )
                send_mail(
                    'Reset your password',
                    f'Click the link to reset your password: {reset_url}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                return Response({'status': 'success'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ResetPasswordView(APIView):
    def post(self, request, uidb64, token):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            try:
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)
                if PasswordResetTokenGenerator().check_token(user, token):
                    user.set_password(serializer.validated_data['newPassword'])
                    user.save()
                    return Response({'status': 'success'}, status=status.HTTP_200_OK)
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CheckStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'status': 'logged in', 'role': request.user.role}, status=status.HTTP_200_OK)

class TwoFactorAuthView(APIView):
    def post(self, request):
        serializer = TwoFactorAuthSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            totp = pyotp.TOTP(user.otp_secret)
            token = totp.now()
            send_mail(
                'Your 2FA Token',
                f'Your 2FA token is: {token}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({'status': '2FA token sent'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyTwoFactorAuthView(APIView):
    def post(self, request):
        serializer = TwoFactorAuthSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            token = serializer.validated_data['twoFactorToken']
            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(token):
                return Response({'status': '2FA verified'}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid 2FA token'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)