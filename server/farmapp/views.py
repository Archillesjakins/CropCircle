from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, views
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.utils.timezone import now
from django.shortcuts import get_object_or_404
from datetime import timedelta
import jwt
import uuid
from django.conf import settings
from django.db import DatabaseError
from rest_framework.permissions import IsAuthenticated

from .models import User, Farmer, Order, Product, Review
from .serializers import (
    RegisterSerializer, LoginSerializer, ChangePasswordSerializer, 
    ForgotPasswordSerializer, ResetPasswordSerializer, OrderDetailSerializer, 
    OrderStatusUpdateSerializer
)

# JWT Utility
def generate_jwt(user):
    payload = {'user_id': user.userId, 'email': user.email}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

# Authentication Views
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

            if not check_password(password, user.password):
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
            if not user.is_active:
                return Response({"error": "Email not verified."}, status=status.HTTP_403_FORBIDDEN)

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

            reset_token = str(uuid.uuid4())
            user.reset_password_token = reset_token
            user.reset_token_created_at = now()
            user.save()

            reset_url = f"http://your-frontend-url.com/reset-password?token={reset_token}"
            send_mail(
                subject="Password Reset Request",
                message=f"Hi {user.name},\n\nClick the link to reset your password:\n\n{reset_url}",
                from_email="no-reply@yourdomain.com",
                recipient_list=[email]
            )
            return Response({"message": "Password reset link sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            try:
                user = User.objects.get(reset_password_token=token)
                if now() - user.reset_token_created_at > timedelta(hours=1):
                    return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

                user.password = make_password(new_password)
                user.reset_password_token = None
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
        return Response({"message": "Successfully signed out."}, status=status.HTTP_200_OK)

# Order and Review Management Views
class OrderDetailView(APIView):
    def get(self, request, farmerId, orderId):
        try:
            farmer = Farmer.objects.get(farmerId=farmerId)
            order = Order.objects.get(orderId=orderId)
            product_ids = [item['productId'] for item in order.orderItems]
            if not Product.objects.filter(productId__in=product_ids, farmer=farmer).exists():
                return Response({"error": "Order not associated with this farmer"}, status=status.HTTP_404_NOT_FOUND)

            serializer = OrderDetailSerializer(order)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Farmer.DoesNotExist:
            return Response({"error": "Farmer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

class UpdateOrderStatusView(APIView):
    def put(self, request, farmerId, orderId):
        try:
            farmer = Farmer.objects.get(farmerId=farmerId)
            order = Order.objects.get(orderId=orderId)
            product_ids = [item['productId'] for item in order.orderItems]
            if not Product.objects.filter(productId__in=product_ids, farmer=farmer).exists():
                return Response({"error": "Order not associated with this farmer"}, status=status.HTTP_404_NOT_FOUND)

            serializer = OrderStatusUpdateSerializer(order, data=request.data, partial=True)
            if serializer.is_valid():
                order.status = serializer.validated_data['status']
                order.save()
                return Response({"message": "Order status updated successfully", "status": order.status}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Farmer.DoesNotExist:
            return Response({"error": "Farmer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

class DeleteOrderView(APIView):
    def delete(self, request, farmerId, orderId):
        try:
            farmer = Farmer.objects.get(farmerId=farmerId)
            order = Order.objects.get(orderId=orderId)
            product_ids = [item['productId'] for item in order.orderItems]
            if not Product.objects.filter(productId__in=product_ids, farmer=farmer).exists():
                return Response({"error": "Order not associated with this farmer"}, status=status.HTTP_404_NOT_FOUND)

            if order.status not in ["pending", "cancelled"]:
                return Response({"error": "Cannot delete a completed or delivered order"}, status=status.HTTP_400_BAD_REQUEST)

            order.status = "cancelled"
            order.save()
            return Response({"message": "Order cancelled successfully"}, status=status.HTTP_200_OK)
        except Farmer.DoesNotExist:
            return Response({"error": "Farmer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

class DeleteReviewView(APIView):
    def delete(self, request, productId, reviewId):
        try:
            review = get_object_or_404(Review, reviewId=reviewId, product__id=productId)
            if review.customer != request.user:
                return Response({"error": "You are not authorized to delete this review."}, status=status.HTTP_403_FORBIDDEN)

            review.delete()
            return Response({"review": {}}, status=status.HTTP_204_NO_CONTENT)
        except DatabaseError:
            return Response({"error": "An error occurred while deleting the review."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
