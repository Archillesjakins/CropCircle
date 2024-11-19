from django.urls import path
from .views import UserListView, UserDetailView, UserStatusUpdateView, LoginView, AdminOnlyView, RegisterView, LoginView, LogoutView, VerifyEmailView, ForgotPasswordView, ResetPasswordView, CheckStatusView, TwoFactorAuthView, VerifyTwoFactorAuthView, ConfirmEmailView
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active)
        )

email_verification_token = EmailVerificationTokenGenerator()

urlpatterns = [
    path('admin/users/', UserListView.as_view(), name='user-list'),
    path('admin/users/<int:userId>/', UserDetailView.as_view(), name='user-detail'),
    path('admin/users/<int:userId>/status/', UserStatusUpdateView.as_view(), name='user-status-update'),
    path('admin/login/', LoginView.as_view(), name='admin-login'),
    path('admin/dashboard/', AdminOnlyView.as_view(), name='admin-dashboard'),
    path('farmer/auth/register/', RegisterView.as_view(), name='farmer-register'),
    path('farmer/auth/login/', LoginView.as_view(), name='farmer-login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('auth/confirm-email/<str:token>/', ConfirmEmailView.as_view(), name='confirm-email'),
    path('auth/forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('auth/reset-password/<str:uidb64>/<str:token>/', ResetPasswordView.as_view(), name='reset-password'),
    path('auth/check-status/', CheckStatusView.as_view(), name='check-status'),
    path('auth/two-factor/', TwoFactorAuthView.as_view(), name='two-factor-auth'),
    path('auth/verify-two-factor/', VerifyTwoFactorAuthView.as_view(), name='verify-two-factor-auth'),

]
