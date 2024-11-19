from django.urls import path
from .views import OrderListView, OrderDetailView, OrderStatusUpdateView, FarmerOrderListView, OrderDetailView, UpdateOrderStatusView, DeleteOrderView

urlpatterns = [
    path('admin/orders/', OrderListView.as_view(), name='order-list'),
    path('admin/orders/<int:orderId>/', OrderDetailView.as_view(), name='order-detail'),
    path('admin/orders/<int:orderId>/status/', OrderStatusUpdateView.as_view(), name='order-status-update'),
    path('farmer/<int:farmerId>/orders/', FarmerOrderListView.as_view(), name='farmer-order-list'),
    path('farmer/<int:farmerId>/orders/<int:orderId>/', OrderDetailView.as_view(), name='order-detail'),
    path('farmer/<int:farmerId>/orders/<int:orderId>/status/', UpdateOrderStatusView.as_view(), name='update-order-status'),
    path('farmer/<int:farmerId>/orders/<int:orderId>/', DeleteOrderView.as_view(), name='delete-order'),
]