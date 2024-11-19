from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from apps.products.models import Product
from apps.orders.models import Order
from apps.admin_activity_logs import models
from .models import Farmer
from .serializers import FarmerOverviewSerializer, RecentOrderSerializer

class FarmerOverviewView(APIView):
    def get(self, request, farmerId):
        try:
            farmer = Farmer.objects.get(farmerId=farmerId)
            totalProducts = Product.objects.filter(farmerId=farmer).count()
            totalSales = Order.objects.filter(orderItems__farmerId=farmer).aggregate(total_sales=models.Sum('totalAmount'))['total_sales'] or 0
            totalOrders = Order.objects.filter(orderItems__farmerId=farmer).count()
            data = {
                "totalProducts": totalProducts,
                "totalSales": totalSales,
                "totalOrders": totalOrders
            }
            serializer = FarmerOverviewSerializer(data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Farmer.DoesNotExist:
            return Response({'error': 'Farmer not found'}, status=status.HTTP_404_NOT_FOUND)

class RecentOrdersView(APIView):
    def get(self, request, farmerId):
        try:
            farmer = Farmer.objects.get(farmerId=farmerId)
            limit = request.query_params.get('limit', 5)
            orders = Order.objects.filter(orderItems__farmerId=farmer).order_by('-createdAt')[:int(limit)]
            serializer = RecentOrderSerializer(orders, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Farmer.DoesNotExist:
            return Response({'error': 'Farmer not found'}, status=status.HTTP_404_NOT_FOUND)