from django.db import models
from apps.users.models import User
from apps.products.models import Product

# Create your models here.
class Order(models.Model):
    orderId = models.AutoField(primary_key=True)
    customerId = models.ForeignKey(User, on_delete=models.CASCADE)
    orderItems = models.JSONField()
    totalAmount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=50)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Order {self.orderId} by {self.customerId.name}"

    class Meta:
        db_table = 'tblOrder'