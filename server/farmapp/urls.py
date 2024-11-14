from django.urls import path
from .views import RegisterView, LoginView, ForgotPasswordView, ResetPasswordView, ChangePasswordView, CheckStatusView, SignoutView

urlpatterns = [
    path('farmer/auth/register/', RegisterView.as_view(), name='register'),
    path('farmer/auth/login/', LoginView.as_view(), name='login'),
    path('farmer/auth/forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('farmer/auth/reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('farmer/auth/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('farmer/auth/check-status/', CheckStatusView.as_view(), name='check-status'),
    path('farmer/auth/signout/', SignoutView.as_view(), name='signout'),
]