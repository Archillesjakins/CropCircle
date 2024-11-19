from django.db import models
from apps.users.models import User
from apps.products.models import Product

# Create your models here.
class Cart(models.Model):
    cartId = models.AutoField(primary_key=True)
    customerId = models.ForeignKey(User, on_delete=models.CASCADE)
    items = models.JSONField()
    totalPrice = models.DecimalField(max_digits=10, decimal_places=2)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Cart {self.cartId} for {self.customerId.name}"

    class Meta:
        db_table = 'tblCart'