# models.py - Simplified
from django.db import models
from django.conf import settings

class UserQuery(models.Model):
    """Stores only the search query generated for each user"""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='search_query'
    )
    query_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Search query for {self.user.email}"