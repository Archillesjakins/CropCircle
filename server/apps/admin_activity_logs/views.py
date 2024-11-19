from rest_framework import generics
from .models import AdminActivityLog
from .serializers import AdminActivityLogSerializer

class AdminActivityLogListView(generics.ListAPIView):
    serializer_class = AdminActivityLogSerializer

    def get_queryset(self):
        queryset = AdminActivityLog.objects.all()
        date = self.request.query_params.get('date', None)
        action_type = self.request.query_params.get('action_type', None)
        admin_user = self.request.query_params.get('admin_user', None)
        if date:
            queryset = queryset.filter(timestamp__date=date)
        if action_type:
            queryset = queryset.filter(action__icontains=action_type)
        if admin_user:
            queryset = queryset.filter(adminId=admin_user)
        return queryset