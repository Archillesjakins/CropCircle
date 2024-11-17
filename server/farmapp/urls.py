from django.urls import path
from .views import DeleteReviewView, OrderDetailView, UpdateOrderStatusView, DeleteOrderView

urlpatterns = [
    # URL for retrieving order details
    path("api/farmer/<int:farmerId>/orders/<int:orderId>", OrderDetailView.as_view(), name="order-detail"),
    
    # URL for updating order status
    path("api/farmer/<int:farmerId>/orders/<int:orderId>/status", UpdateOrderStatusView.as_view(), name="update-order-status"),
    
    # URL for deleting an order (or marking it as cancelled, depending on logic)
    path("api/farmer/<int:farmerId>/orders/<int:orderId>/delete", DeleteOrderView.as_view(), name="delete-order"),

    # URL for deleting a review
    path("api/product/<int:productId>/reviews/<int:reviewId>", DeleteReviewView.as_view(), name="delete-review"),
]
