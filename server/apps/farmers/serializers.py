from rest_framework import serializers
from apps.products.models import Product
from apps.orders.models import Order

class FarmerOverviewSerializer(serializers.Serializer):
    totalProducts = serializers.IntegerField()
    totalSales = serializers.DecimalField(max_digits=10, decimal_places=2)
    totalOrders = serializers.IntegerField()

class RecentOrderSerializer(serializers.ModelSerializer):
    productName = serializers.CharField(source='orderItems.productName')
    quantity = serializers.IntegerField(source='orderItems.quantity')
    price = serializers.DecimalField(source='orderItems.price', max_digits=10, decimal_places=2)
    orderDate = serializers.DateTimeField(source='createdAt')

    class Meta:
        model = Order
        fields = ['orderId', 'productName', 'quantity', 'price', 'status', 'orderDate']