# main/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone 

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    theme = models.CharField(max_length=20, default='dark')
    auto_clear = models.BooleanField(default=True)
    secure_wipe = models.BooleanField(default=True)
    audit_trail = models.BooleanField(default=False)
    encryption_algorithm = models.CharField(max_length=20, default='aes-256')
    key_derivation = models.CharField(max_length=20, default='pbkdf2')
    font_size = models.CharField(max_length=10, default='medium')
    language = models.CharField(max_length=10, default='en')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} Profile"

class EncryptionHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    operation_type = models.CharField(max_length=10, choices=[('encrypt', 'Encrypt'), ('decrypt', 'Decrypt')])
    input_text = models.TextField()
    output_text = models.TextField()
    key_used = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'Encryption Histories'

    def __str__(self):
        return f"{self.user.username} - {self.operation_type} - {self.created_at}"

class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    ip_address = models.CharField(max_length=45, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} session at {self.login_time.strftime('%Y-%m-%d %H:%M')}"