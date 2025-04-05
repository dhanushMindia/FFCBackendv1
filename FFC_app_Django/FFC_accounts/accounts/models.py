from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
	first_name = models.CharField(max_length = 150, blank = True)
	last_name = models.CharField(max_length =150, blank = True)
	email = models.EmailField(unique=True, blank=False)

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['username']

	def __str__(self):
		return self.email
		
