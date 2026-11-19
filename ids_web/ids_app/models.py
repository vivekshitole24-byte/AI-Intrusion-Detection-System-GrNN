from django.db import models
from django.contrib.auth.models import AbstractUser


class FailedLoginAttempt(models.Model):
    username = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    failed_attempts = models.PositiveIntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Failed login by {self.username} from {self.ip_address}"


def track_failed_login():
    from ids_app.models import FailedLoginAttempt  # ✅ Moved inside function



class BlockedUser(models.Model):
    username = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    blocked_until = models.DateTimeField()
    is_blocked = models.BooleanField(default=True)

    def __str__(self):
        return f"Blocked {self.username} from {self.ip_address} until {self.blocked_until}"

class CustomUser(AbstractUser):  # Extending Django's built-in User model
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    failed_attempts = models.IntegerField(default=0)
    is_blocked = models.BooleanField(default=False)
    blocked_until = models.DateTimeField(null=True, blank=True)

    groups = models.ManyToManyField(
        "auth.Group",
        related_name="customuser_set",  # ✅ Fixes conflict
        blank=True
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="customuser_permissions",  # ✅ Fixes conflict
        blank=True
    )

    def __str__(self):
        return self.username