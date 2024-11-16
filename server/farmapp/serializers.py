from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import User, Order, Product

# User Management Serializers
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'role', 'phone', 'address']

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

# Order Management Serializers
class OrderDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for displaying detailed information about an order.
    """
    orderId = serializers.IntegerField()  # Removed 'source' argument
    customerName = serializers.CharField(source='customer.name')
    productName = serializers.SerializerMethodField()
    quantity = serializers.SerializerMethodField()
    totalPrice = serializers.DecimalField(source='totalAmount', max_digits=10, decimal_places=2)
    orderStatus = serializers.CharField(source='status')
    dateOrdered = serializers.DateTimeField(source='createdAt')
    deliveryDate = serializers.DateTimeField()
    address = serializers.CharField(source='customer.address')
    phone = serializers.CharField(source='customer.phone', allow_null=True, required=False)

    def get_productName(self, obj):
        """
        Retrieves the name of the product from the Product model based on productId.
        """
        product_ids = [item['productId'] for item in obj.orderItems]
        products = Product.objects.filter(productId__in=product_ids)
        return ', '.join([product.productName for product in products])

    def get_quantity(self, obj):
        """
        Retrieves the quantity of the product ordered.
        """
        return sum(item.get('quantity', 0) for item in obj.orderItems)

    class Meta:
        model = Order
        fields = ['orderId', 'customerName', 'productName', 'phone', 'orderItems', 'totalPrice', 'orderStatus', 'address', 'quantity', 'dateOrdered', 'deliveryDate']

class OrderStatusUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating the status of an order.
    """
    status = serializers.ChoiceField(choices=Order.ORDER_STATUS_CHOICES)

    def validate_status(self, value):
        """
        Validates allowed status transitions for the order.
        """
        current_status = self.instance.status
        allowed_transitions = {
            'pending': ['shipped', 'cancelled'],
            'shipped': ['delivered'],
            'delivered': [],
        }

        if value not in allowed_transitions.get(current_status, []):
            raise serializers.ValidationError(
                f"Invalid status transition from '{current_status}' to '{value}'"
            )
        return value

    class Meta:
        model = Order
        fields = ['status']
