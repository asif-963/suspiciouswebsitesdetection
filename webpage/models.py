from django.db import models
from django.contrib.auth.models import User


class Message(models.Model):
    user_name=models.CharField(max_length=200, null=False ,blank=False)
    user_email=models.CharField(max_length=200, null=False ,blank=False)
    user_message=models.TextField()

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    forget_password_token = models.CharField(max_length=100, blank=True, null=True)
    forget_password_token_created_at = models.DateTimeField(blank=True, null=True)
    password_reset_link_used = models.BooleanField(default=False)
    last_password_change = models.DateTimeField(blank=True, null=True)


    def __str__(self):
        return self.user.username

class SuspiciousWebsite(models.Model):
    url = models.URLField(max_length=200, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):

        index = SuspiciousWebsite.objects.filter(created_at__lte=self.created_at).count()
        return f"{index} - {self.url}"


class SqlinjectionWebsites(models.Model):
    url = models.URLField(max_length=200, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):

        index = SqlinjectionWebsites.objects.filter(created_at__lte=self.created_at).count()
        return f"{index} - {self.url}"