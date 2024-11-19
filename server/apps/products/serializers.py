from rest_framework import serializers
from .models import Product

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['productId', 'farmerId', 'productName', 'description', 'category', 'unitPrice', 'stockQuantity', 'productImage', 'status', 'createdAt', 'updatedAt']