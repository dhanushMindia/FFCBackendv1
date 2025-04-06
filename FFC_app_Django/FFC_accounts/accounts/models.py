from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import random                    
from datetime import timedelta 
    # --- ADD THIS METHOD ---
    # --- ADD THIS METHOD ---

class User(AbstractUser):

	first_name = models.CharField(max_length = 150, blank = True)
	last_name = models.CharField(max_length =150, blank = True)
	email = models.EmailField(unique=True, blank=False)
	is_active = models.BooleanField(default=False) # User starts as inactive
	otp = models.CharField(max_length=6, null=True, blank=True)
	otp_expiry = models.DateTimeField(null=True, blank=True)

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = []

	def __str__(self):
		return self.email
	def generate_otp(self):
		self.otp = str(random.randint(100000,999999))
		self.otp_expiry=timezone.now()+timedelta(minutes=10)
		self.save(update_fields=['otp','otp_expiry'])
		print(f"Generated OTP {self.otp} for {self.email}, expires at {self.otp_expiry}")
		