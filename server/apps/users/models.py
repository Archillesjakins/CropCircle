from django.db import models
from django.contrib.auth.models import AbstractUser, User
import pyotp
from datetime import datetime, timedelta
from django.utils import timezone


from django.contrib.auth.models import AbstractUser
from django.db import models
import pyotp

class User(AbstractUser):
    userId = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=50, choices=[('farmer', 'Farmer'), ('customer', 'Customer'), ('admin', 'Admin')])
    phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)
    otp_secret = models.CharField(max_length=50, default=pyotp.random_base32)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'role']

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'tblUser'


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    # def save(self, *args, **kwargs):
    #     if not self.pk:
    #         super().save(*args, **kwargs)
    #     self.expires_at = self.created_at + timedelta(minutes=10)  # OTP valid for 10 minutes
    #     super().save(*args, **kwargs)

    def save(self, *args, **kwargs):
        # Ensure created_at is set before calculating expires_at
        if not self.created_at:
            self.created_at = timezone.now()
        
        # Calculate expires_at if not already set
        if not self.expires_at:
            self.expires_at = self.created_at + timedelta(minutes=10)
        
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"OTP for {self.user.username}"