from django.urls import path
from .views import ReviewListView, ReviewStatusUpdateView, ProductReviewListView, AddReviewView, EditReviewView, DeleteReviewView

urlpatterns = [
    path('admin/reviews/', ReviewListView.as_view(), name='review-list'),
    path('admin/reviews/<int:review_id>/status/', ReviewStatusUpdateView.as_view(), name='review-status-update'),
    path('product/<int:productId>/reviews/', ProductReviewListView.as_view(), name='product-reviews'),
    path('product/<int:productId>/reviews/', AddReviewView.as_view(), name='add-review'),
    path('product/<int:productId>/reviews/<int:reviewId>/', EditReviewView.as_view(), name='edit-review'),
    path('product/<int:productId>/reviews/<int:reviewId>/', DeleteReviewView.as_view(), name='delete-review'),
]
