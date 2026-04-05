from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission

class URLCheck(models.Model):
    url = models.URLField(max_length=500)
    is_phishing = models.BooleanField(default=False)
    analysis_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url

class User(models.Model):
    uid = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.name
    
qr_code_url = models.CharField(max_length=255, default="https://example.com")  # For URL field
scan_date = models.DateTimeField(auto_now_add=True)  # For timestamp


class ScannedQR(models.Model):
    url = models.URLField()
    status = models.CharField(max_length=20)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.status}"
