from django.db import models
from apps.users.models import User
from apps.products.models import Product

# Create your models here.
class Review(models.Model):
    reviewId = models.AutoField(primary_key=True)
    productId = models.ForeignKey(Product, on_delete=models.CASCADE)
    customerId = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.IntegerField()
    comment = models.TextField()
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Review {self.reviewId} for {self.productId.productName} by {self.customerId.name}"

    class Meta:
        db_table = 'tblReview'