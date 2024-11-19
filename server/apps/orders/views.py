from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Order
from .serializers import OrderSerializer
from apps.farmers.models import Farmer



class OrderListView(generics.ListAPIView):
    serializer_class = OrderSerializer

    def get_queryset(self):
        queryset = Order.objects.all()
        status = self.request.query_params.get('status', None)
        payment_method = self.request.query_params.get('payment_method', None)
        date_range = self.request.query_params.get('date_range', None)
        if status:
            queryset = queryset.filter(status=status)
        if payment_method:
            queryset = queryset.filter(payment_method=payment_method)
        if date_range:
            start_date, end_date = date_range.split(',')
            queryset = queryset.filter(createdAt__range=[start_date, end_date])
        return queryset

class OrderDetailView(generics.RetrieveAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    lookup_field = 'orderId'

class OrderStatusUpdateView(APIView):
    def put(self, request, orderId):
        try:
            order = Order.objects.get(orderId=orderId)
            status = request.data.get('status')
            order.status = status
            order.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
        
class FarmerOrderListView(generics.ListAPIView):
    serializer_class = OrderSerializer

    def get_queryset(self):
        farmerId = self.kwargs['farmerId']
        return Order.objects.filter(orderItems__farmerId=farmerId)

class OrderDetailView(generics.RetrieveAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    lookup_field = 'orderId'

class UpdateOrderStatusView(APIView):
    def put(self, request, farmerId, orderId):
        try:
            order = Order.objects.get(orderId=orderId, orderItems__farmerId=farmerId)
            status = request.data.get('status')
            order.status = status
            order.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

class DeleteOrderView(APIView):
    def delete(self, request, farmerId, orderId):
        try:
            order = Order.objects.get(orderId=orderId, orderItems__farmerId=farmerId)
            order.delete()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)