from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Cart
from .serializers import CartSerializer, CartItemSerializer
from apps.users.models import User
from apps.products.models import Product

class CustomerCartView(APIView):
    def get(self, request, customerId):
        try:
            cart = Cart.objects.get(customerId=customerId)
            serializer = CartSerializer(cart)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Cart.DoesNotExist:
            return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)

class AddCartItemView(APIView):
    def post(self, request, customerId):
        try:
            cart, created = Cart.objects.get_or_create(customerId=customerId)
            item_data = request.data
            product_id = item_data['productId']
            quantity = item_data['quantity']
            for item in cart.items:
                if item['productId'] == product_id:
                    item['quantity'] += quantity
                    break
            else:
                cart.items.append({'productId': product_id, 'quantity': quantity})
            cart.totalPrice += Product.objects.get(productId=product_id).unitPrice * quantity
            cart.save()
            serializer = CartSerializer(cart)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'Customer not found'}, status=status.HTTP_404_NOT_FOUND)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class UpdateCartItemView(APIView):
    def put(self, request, customerId, productId):
        try:
            cart = Cart.objects.get(customerId=customerId)
            quantity = request.data['quantity']
            for item in cart.items:
                if item['productId'] == productId:
                    cart.totalPrice -= Product.objects.get(productId=productId).unitPrice * item['quantity']
                    item['quantity'] = quantity
                    cart.totalPrice += Product.objects.get(productId=productId).unitPrice * quantity
                    break
            cart.save()
            serializer = CartSerializer(cart)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Cart.DoesNotExist:
            return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class RemoveCartItemView(APIView):
    def delete(self, request, customerId, productId):
        try:
            cart = Cart.objects.get(customerId=customerId)
            for item in cart.items:
                if item['productId'] == productId:
                    cart.totalPrice -= Product.objects.get(productId=productId).unitPrice * item['quantity']
                    cart.items.remove(item)
                    break
            cart.save()
            serializer = CartSerializer(cart)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Cart.DoesNotExist:
            return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class ClearCartView(APIView):
    def delete(self, request, customerId):
        try:
            cart = Cart.objects.get(customerId=customerId)
            cart.items = []
            cart.totalPrice = 0
            cart.save()
            serializer = CartSerializer(cart)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Cart.DoesNotExist:
            return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)