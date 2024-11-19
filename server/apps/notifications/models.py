from django.db import models
from apps.users.models import User

# Create your models here.
class Notification(models.Model):
    notificationId = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    createdAt = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification {self.notificationId} for {self.user.name}"

    class Meta:
        db_table = 'tblNotification'