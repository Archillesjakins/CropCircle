from django.urls import path
from .views import SalesReportView, UserActivityReportView, ProductPerformanceReportView

urlpatterns = [
    path('admin/reports/sales/', SalesReportView.as_view(), name='sales-report'),
    path('admin/reports/users/', UserActivityReportView.as_view(), name='user-activity-report'),
    path('admin/reports/products/', ProductPerformanceReportView.as_view(), name='product-performance-report'),
]