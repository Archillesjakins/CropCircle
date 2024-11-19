from rest_framework import serializers
from .models import Order

class OrderSerializer(serializers.ModelSerializer):
    customerName = serializers.CharField(source='customerId.name')
    productName = serializers.CharField(source='orderItems.productName')
    quantity = serializers.IntegerField(source='orderItems.quantity')
    totalPrice = serializers.DecimalField(source='totalAmount', max_digits=10, decimal_places=2)
    dateOrdered = serializers.DateTimeField(source='createdAt')
    deliveryDate = serializers.DateTimeField(source='updatedAt')

    class Meta:
        model = Order
        fields = ['orderId', 'customerName', 'productName', 'quantity', 'totalPrice', 'status', 'dateOrdered', 'deliveryDate', 'address']