from django.urls import path
from .views import AdminActivityLogListView

urlpatterns = [
    path('admin/activity-log/', AdminActivityLogListView.as_view(), name='admin-activity-log-list'),
]