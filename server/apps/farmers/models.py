from django.db import models
from apps.users.models import User

# Create your models here.
class Farmer(models.Model):
    farmerId = models.AutoField(primary_key=True)
    userId = models.ForeignKey(User, on_delete=models.CASCADE)
    farmName = models.CharField(max_length=255)
    location = models.TextField()
    farmType = models.CharField(max_length=50)
    certifications = models.TextField(blank=True, null=True)
    verificationStatus = models.CharField(max_length=50)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.farmName

    class Meta:
        db_table = 'tblFarmer'