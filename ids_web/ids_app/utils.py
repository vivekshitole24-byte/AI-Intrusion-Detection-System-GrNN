from django.utils import timezone
from .models import BlockedUser

def unblock_expired_users():
    current_time = timezone.now()
    expired_users = BlockedUser.objects.filter(blocked_until__lte=current_time, is_blocked=True)

    for user in expired_users:
        user.is_blocked = False
        user.save()

    return expired_users
