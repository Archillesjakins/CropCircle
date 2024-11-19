from django.urls import path
from .views import PendingProductListView, ApproveProductView, RejectProductView, ProductListView, InventoryListView, UpdateStockView, FarmerProductListView, AddProductView, EditProductView, DeleteProductView, ProductDetailView

urlpatterns = [
    path('admin/products/pending/', PendingProductListView.as_view(), name='pending-product-list'),
    path('admin/products/<int:product_id>/approve/', ApproveProductView.as_view(), name='approve-product'),
    path('admin/products/<int:product_id>/reject/', RejectProductView.as_view(), name='reject-product'),
    path('admin/products/', ProductListView.as_view(), name='product-list'),
    path('admin/inventory/', InventoryListView.as_view(), name='inventory-list'),
    path('admin/inventory/<int:product_id>/', UpdateStockView.as_view(), name='update-stock'),
    path('farmer/<int:farmerId>/products/', FarmerProductListView.as_view(), name='farmer-product-list'),
    path('farmer/<int:farmerId>/products/', AddProductView.as_view(), name='add-product'),
    path('farmer/<int:farmerId>/products/<int:productId>/', EditProductView.as_view(), name='edit-product'),
    path('farmer/<int:farmerId>/products/<int:productId>/', DeleteProductView.as_view(), name='delete-product'),
    path('farmer/<int:farmerId>/products/<int:productId>/', ProductDetailView.as_view(), name='product-detail'),
]