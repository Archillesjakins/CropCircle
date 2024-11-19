from django.db import models
from apps.users.models import User

# Create your models here.
class AdminActivityLog(models.Model):
    logId = models.AutoField(primary_key=True)
    adminId = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.TextField()
    targetId = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Log {self.logId} by {self.adminId.name}"

    class Meta:
        db_table = 'tblAdminActivityLog'