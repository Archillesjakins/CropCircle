from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Product
from .serializers import ProductSerializer
from apps.farmers.models import Farmer




class PendingProductListView(generics.ListAPIView):
    serializer_class = ProductSerializer

    def get_queryset(self):
        return Product.objects.filter(status='pending')

class ApproveProductView(APIView):
    def put(self, request, product_id):
        try:
            product = Product.objects.get(productId=product_id)
            product.status = 'approved'
            product.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class RejectProductView(APIView):
    def put(self, request, product_id):
        try:
            product = Product.objects.get(productId=product_id)
            rejection_reason = request.data.get('rejection_reason', '')
            product.status = 'rejected'
            product.save()
            return Response({'status': 'success', 'rejection_reason': rejection_reason}, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class ProductListView(generics.ListAPIView):
    serializer_class = ProductSerializer

    def get_queryset(self):
        queryset = Product.objects.all()
        category = self.request.query_params.get('category', None)
        if category:
            queryset = queryset.filter(category=category)
        return queryset
    
class InventoryListView(generics.ListAPIView):
    serializer_class = ProductSerializer

    def get_queryset(self):
        queryset = Product.objects.all()
        product = self.request.query_params.get('product', None)
        category = self.request.query_params.get('category', None)
        if product:
            queryset = queryset.filter(productName__icontains=product)
        if category:
            queryset = queryset.filter(category=category)
        return queryset

class UpdateStockView(APIView):
    def put(self, request, product_id):
        try:
            product = Product.objects.get(productId=product_id)
            stock_quantity = request.data.get('stockQuantity')
            product.stockQuantity = stock_quantity
            product.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)
        
class FarmerProductListView(generics.ListAPIView):
    serializer_class = ProductSerializer

    def get_queryset(self):
        farmerId = self.kwargs['farmerId']
        return Product.objects.filter(farmerId=farmerId)

class AddProductView(APIView):
    def post(self, request, farmerId):
        try:
            farmer = Farmer.objects.get(farmerId=farmerId)
            data = request.data
            data['farmerId'] = farmer.farmerId
            serializer = ProductSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Farmer.DoesNotExist:
            return Response({'error': 'Farmer not found'}, status=status.HTTP_404_NOT_FOUND)

class EditProductView(APIView):
    def put(self, request, farmerId, productId):
        try:
            product = Product.objects.get(productId=productId, farmerId=farmerId)
            serializer = ProductSerializer(product, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class DeleteProductView(APIView):
    def delete(self, request, farmerId, productId):
        try:
            product = Product.objects.get(productId=productId, farmerId=farmerId)
            product.status = 'out of stock'  # Soft delete
            product.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class ProductDetailView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    lookup_field = 'productId'