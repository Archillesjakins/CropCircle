from django.urls import path
from .views import NotificationListView, MarkNotificationReadView, SendNotificationView

urlpatterns = [
    path('admin/notifications/', NotificationListView.as_view(), name='notification-list'),
    path('admin/notifications/<int:notification_id>/read/', MarkNotificationReadView.as_view(), name='mark-notification-read'),
    path('admin/notifications/send/', SendNotificationView.as_view(), name='send-notification'),
]