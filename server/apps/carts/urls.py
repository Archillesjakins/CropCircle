from django.urls import path
from .views import CustomerCartView, AddCartItemView, UpdateCartItemView, RemoveCartItemView, ClearCartView

urlpatterns = [
    path('customer/<int:customerId>/cart/', CustomerCartView.as_view(), name='customer-cart'),
    path('customer/<int:customerId>/cart/items/', AddCartItemView.as_view(), name='add-cart-item'),
    path('customer/<int:customerId>/cart/items/<int:productId>/', UpdateCartItemView.as_view(), name='update-cart-item'),
    path('customer/<int:customerId>/cart/items/<int:productId>/', RemoveCartItemView.as_view(), name='remove-cart-item'),
    path('customer/<int:customerId>/cart/', ClearCartView.as_view(), name='clear-cart'),
]