from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Review
from .serializers import ReviewSerializer
from apps.products.models import Product
from apps.users.models import User


class ReviewListView(generics.ListAPIView):
    serializer_class = ReviewSerializer

    def get_queryset(self):
        queryset = Review.objects.all()
        product = self.request.query_params.get('product', None)
        rating = self.request.query_params.get('rating', None)
        status = self.request.query_params.get('status', None)
        if product:
            queryset = queryset.filter(productId=product)
        if rating:
            queryset = queryset.filter(rating=rating)
        if status:
            queryset = queryset.filter(status=status)
        return queryset

class ReviewStatusUpdateView(APIView):
    def put(self, request, review_id):
        try:
            review = Review.objects.get(reviewId=review_id)
            status = request.data.get('status')
            review.status = status
            review.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Review.DoesNotExist:
            return Response({'error': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)

class ProductReviewListView(generics.ListAPIView):
    serializer_class = ReviewSerializer

    def get_queryset(self):
        productId = self.kwargs['productId']
        return Review.objects.filter(productId=productId)

class AddReviewView(APIView):
    def post(self, request, productId):
        try:
            product = Product.objects.get(productId=productId)
            customer = request.user
            data = request.data
            data['productId'] = product.productId
            data['customerId'] = customer.userId
            serializer = ReviewSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class EditReviewView(APIView):
    def put(self, request, productId, reviewId):
        try:
            review = Review.objects.get(reviewId=reviewId, productId=productId, customerId=request.user.userId)
            serializer = ReviewSerializer(review, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Review.DoesNotExist:
            return Response({'error': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)

class DeleteReviewView(APIView):
    def delete(self, request, productId, reviewId):
        try:
            review = Review.objects.get(reviewId=reviewId, productId=productId, customerId=request.user.userId)
            review.delete()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Review.DoesNotExist:
            return Response({'error': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)