from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from apps.users.models import User
from .models import Notification
from .serializers import NotificationSerializer

class NotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer

    def get_queryset(self):
        return Notification.objects.all()

class MarkNotificationReadView(APIView):
    def put(self, request, notification_id):
        try:
            notification = Notification.objects.get(notificationId=notification_id)
            notification.is_read = True
            notification.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({'error': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)

class SendNotificationView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        message = request.data.get('message')
        try:
            user = User.objects.get(userId=user_id)
            notification = Notification.objects.create(user=user, message=message)
            return Response({'status': 'success', 'notification_id': notification.notificationId}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)