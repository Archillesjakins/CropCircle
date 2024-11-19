from rest_framework import serializers
from .models import AdminActivityLog

class AdminActivityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminActivityLog
        fields = ['logId', 'adminId', 'action', 'targetId', 'timestamp']