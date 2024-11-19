from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from apps.orders.models import Order
from apps.users.models import User
from apps.products.models import Product

class SalesReportView(APIView):
    def get(self, request):
        # Implement logic to generate sales report
        sales_data = {
            "total_sales": 10000,
            "total_orders": 200,
            "total_revenue": 50000
        }
        return Response(sales_data, status=status.HTTP_200_OK)

class UserActivityReportView(APIView):
    def get(self, request):
        # Implement logic to generate user activity report
        user_activity_data = {
            "total_users": 1000,
            "active_users": 800,
            "inactive_users": 200
        }
        return Response(user_activity_data, status=status.HTTP_200_OK)

class ProductPerformanceReportView(APIView):
    def get(self, request):
        # Implement logic to generate product performance report
        product_performance_data = {
            "top_products": [
                {"product_name": "Product 1", "sales": 1000},
                {"product_name": "Product 2", "sales": 800}
            ],
            "total_products": 100
        }
        return Response(product_performance_data, status=status.HTTP_200_OK)