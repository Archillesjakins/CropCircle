from django.urls import path
from .views import FarmerOverviewView, RecentOrdersView

urlpatterns = [
    path('farmer/<int:farmerId>/overview/', FarmerOverviewView.as_view(), name='farmer-overview'),
    path('farmer/<int:farmerId>/orders/', RecentOrdersView.as_view(), name='recent-orders'),
]