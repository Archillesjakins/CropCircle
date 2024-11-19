from rest_framework import serializers
from .models import Cart

class CartItemSerializer(serializers.Serializer):
    productId = serializers.IntegerField()
    quantity = serializers.IntegerField()

class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True)

    class Meta:
        model = Cart
        fields = ['cartId', 'customerId', 'items', 'totalPrice', 'createdAt', 'updatedAt']