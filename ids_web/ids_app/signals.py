from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver
from django.utils import timezone
from .models import FailedLoginAttempt, BlockedUser
import datetime

# Track failed login attempts
@receiver(user_login_failed)
def track_failed_login(sender, credentials, request, **kwargs):
    username = credentials.get('username', '')
    ip_address = request.META.get('REMOTE_ADDR', '')
    
    # Update or create the failed login attempt record
    attempt, created = FailedLoginAttempt.objects.get_or_create(
        username=username, ip_address=ip_address,
    )
    
    attempt.failed_attempts += 1
    attempt.timestamp = timezone.now()  # Update timestamp
    attempt.save()

    # Check if user has failed 5 times
    if attempt.failed_attempts >= 5:
        # Block the user
        block_time = timezone.now() + datetime.timedelta(hours=1)  # Block for 1 hour
        BlockedUser.objects.create(
            username=username,
            ip_address=ip_address,
            blocked_until=block_time,
            is_blocked=True
        )
