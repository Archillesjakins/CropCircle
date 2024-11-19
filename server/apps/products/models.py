from django.db import models
from apps.farmers.models import Farmer

# Create your models here.
class Product(models.Model):
    productId = models.AutoField(primary_key=True)
    farmerId = models.ForeignKey(Farmer, on_delete=models.CASCADE)
    productName = models.CharField(max_length=255)
    description = models.TextField()
    category = models.CharField(max_length=50)
    unitPrice = models.DecimalField(max_digits=10, decimal_places=2)
    stockQuantity = models.IntegerField()
    productImage = models.ImageField(upload_to='products/')
    status = models.CharField(max_length=50, default='in stock')
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.productName

    class Meta:
        db_table = 'tblProduct'