from django.db import DatabaseError
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import status, views
from .serializers import OrderDetailSerializer, OrderStatusUpdateSerializer
from .models import Farmer, Order, Product, Review, User
from rest_framework.views import APIView


class OrderDetailView(APIView):
    """
    Retrieve detailed information of a specific order for a given farmer.

    URL Parameters:
        - farmerId (int): ID of the farmer.
        - orderId (int): ID of the order.

    Validations:
        - Ensures the farmer exists.
        - Checks if the order exists and contains products from this farmer.

    Returns:
        - 200 OK: Detailed information of the order.
        - 404 Not Found: If the farmer or order is not found or not associated with the farmer.
    """

    def get(self, request, farmerId, orderId):
        # Validate Farmer
        try:
            farmer = Farmer.objects.get(farmerId=farmerId)
        except Farmer.DoesNotExist:
            return Response({"error": "Farmer not found"}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve Order and Validate Association with Farmer's Products
        try:
            order = Order.objects.get(orderId=orderId)
            product_ids = [item['productId'] for item in order.orderItems]
            farmer_products = Product.objects.filter(productId__in=product_ids, farmer=farmer)

            if not farmer_products.exists():
                return Response({"error": "Order does not contain products from this farmer"}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the order details
        serializer = OrderDetailSerializer(order)

        # Return the serialized data
        return Response(serializer.data, status=status.HTTP_200_OK)



class UpdateOrderStatusView(views.APIView):
    """
    Update the status of an order for a specific farmer, with validation for allowed transitions.
    
    URL Parameters:
        - farmerId (int): ID of the farmer.
        - orderId (int): ID of the order.
    
    Request Body:
        - status (str): New status of the order.
    """

    def put(self, request, farmerId, orderId):
        # Validate Farmer and Order
        try:
            # Check if the farmer exists
            farmer = Farmer.objects.get(farmerId=farmerId)
            # Check if the order exists
            order = Order.objects.get(orderId=orderId)

            # Check if the order contains products from this farmer
            product_ids = [item['productId'] for item in order.orderItems]
            if not Product.objects.filter(productId__in=product_ids, farmer=farmer).exists():
                return Response({"error": "Order does not contain products from this farmer"}, status=status.HTTP_404_NOT_FOUND)

        except Farmer.DoesNotExist:
            return Response({"error": "Farmer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        # Use the serializer for status validation
        serializer = OrderStatusUpdateSerializer(order, data=request.data, partial=True)

        # Validate the serializer
        if serializer.is_valid():
            # Update and save status
            order.status = serializer.validated_data['status']
            order.save()
            
            return Response({"message": "Order status updated successfully", "status": order.status}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteOrderView(views.APIView):
    """
    Delete (or cancel) an order for a specific farmer. Allows for soft deletion where
    the order status is changed to "Cancelled" instead of being permanently deleted.

    URL Parameters:
        - farmerId (int): ID of the farmer.
        - orderId (int): ID of the order.

    Validations:
        - Checks if the farmer and order exist.
        - Ensures the order is linked to the specified farmer.
        - Restricts deletion for orders in "Completed" or "Delivered" status.

    Returns:
        - 200 OK: Order cancelled.
        - 400 Bad Request: If the order cannot be deleted.
        - 404 Not Found: If the farmer or order is not found.
    """

    def delete(self, request, farmerId, orderId):
        # Validate Farmer and Order
        try:
            # Verify farmer existence
            farmer = Farmer.objects.get(farmerId=farmerId)
            
            # Verify order existence and ownership
            order = Order.objects.get(orderId=orderId)
            product_ids = [item['productId'] for item in order.orderItems]
            
            # Check if the order includes products that belong to the specified farmer
            if not Product.objects.filter(productId__in=product_ids, farmer=farmer).exists():
                return Response({"error": "Order not associated with this farmer"}, status=status.HTTP_404_NOT_FOUND)

        except Farmer.DoesNotExist:
            return Response({"error": "Farmer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        # Restrict Deletion Based on Order Status
        if order.status not in ["pending", "cancelled"]:
            return Response({"error": "Cannot delete a completed or delivered order"}, status=status.HTTP_400_BAD_REQUEST)

        # Soft Delete by Setting Status to "Cancelled"
        order.status = "cancelled"
        order.save()

        # Return Success Response
        return Response({"message": "Order cancelled successfully"}, status=status.HTTP_200_OK)



class DeleteReviewView(views.APIView):
    """
    Endpoint: DELETE /api/product/:productId/reviews/:reviewId
    Allows a customer to delete their review for a specific product.
    
    Validations:
        - Ensure that productId and reviewId are valid.
        - Check that the review belongs to the customer making the request.
    
    Responses:
        - 204 No Content: Review successfully deleted.
        - 403 Forbidden: Review does not belong to the customer making the request.
        - 404 Not Found: Product or review not found.
        - 500 Internal Server Error: Database error during deletion.
    """
    
    def delete(self, request, productId, reviewId):
        # Validate Product and Review IDs
        try:
            # Check if the review exists and is associated with the specified product
            review = get_object_or_404(Review, reviewId=reviewId, product__id=productId)
            
            # Check if the review belongs to the requesting user
            if review.customer != request.user:
                return Response({"error": "You are not authorized to delete this review."}, status=status.HTTP_403_FORBIDDEN)

            # Attempt to delete the review from the database
            review.delete()
            return Response({"review": {}}, status=status.HTTP_204_NO_CONTENT)

        except DatabaseError:
            # Step 4: Handle potential database errors during deletion
            return Response({"error": "An error occurred while attempting to delete the review."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)