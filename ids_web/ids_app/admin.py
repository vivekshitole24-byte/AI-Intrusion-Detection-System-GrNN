from django.contrib import admin
from django.contrib.staticfiles.storage import staticfiles_storage
from django.utils.html import format_html
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.admin import UserAdmin
from .models import FailedLoginAttempt, BlockedUser, CustomUser

# ✅ Unregister models if they are already registered to avoid duplication
for model in [CustomUser, BlockedUser, FailedLoginAttempt]:
    if model in admin.site._registry:
        admin.site.unregister(model)


# 🔥 Custom Cyberpunk-Themed Admin Panel
class CustomAdminSite(AdminSite):
    """Custom Django Admin Panel with a Cyberpunk Theme"""

    site_header = "🔥 Cyberpunk IDS Admin"
    site_title = "Cyberpunk IDS"
    index_title = "Welcome to the Cyberpunk IDS Admin"

    def each_context(self, request):
        """Inject custom CSS for Cyberpunk styling"""
        context = super().each_context(request)
        context["css_files"] = [staticfiles_storage.url("ids_app/css/admin_theme.css")]
        return context


# ✅ Use the custom admin panel instead of the default one
custom_admin_site = CustomAdminSite(name="custom_admin")


# ✅ Register Failed Login Attempts Model in Admin
@admin.register(FailedLoginAttempt)
class FailedLoginAttemptAdmin(admin.ModelAdmin):
    """Admin Panel for viewing failed login attempts"""

    list_display = ['username', 'ip_address', 'failed_attempts', 'timestamp']
    search_fields = ['username', 'ip_address']
    list_filter = ['timestamp']


# ✅ Register Blocked Users Model in Admin (With Unblock Action)
@admin.register(BlockedUser)
class BlockedUserAdmin(admin.ModelAdmin):
    """Admin Panel for managing blocked users"""

    list_display = ['username', 'ip_address', 'blocked_until', 'is_blocked']
    search_fields = ['username', 'ip_address']
    list_filter = ['is_blocked']
    actions = ['unblock_selected_users']  # ✅ Allow manual unblocking

    def unblock_selected_users(self, request, queryset):
        """Admin Action: Unblock selected users"""
        for user in queryset:
            if user.is_blocked:
                user.is_blocked = False
                user.blocked_until = None  # ✅ Clear block time
                user.save()
                self.message_user(request, f"✅ Unblocked {user.username} from {user.ip_address}.")
            else:
                self.message_user(request, f"{user.username} is already unblocked.")

    unblock_selected_users.short_description = "Unblock selected users"


# ✅ Custom Admin Panel for Managing Public Users
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """
    Admin Panel for managing users who signed up via public login.
    - Hides staff and superusers (Only public signups will be shown).
    """

    list_display = ['username', 'email', 'is_active', 'failed_attempts', 'is_blocked', 'blocked_until']
    search_fields = ['username', 'email']
    list_filter = ['is_blocked']

    def get_queryset(self, request):
        """Show only public users (hide admin & staff users)"""
        qs = super().get_queryset(request)
        return qs.filter(is_staff=False, is_superuser=False)  # ✅ Hide admin users


# ✅ Register models with the custom admin site
custom_admin_site.register(FailedLoginAttempt, FailedLoginAttemptAdmin)
custom_admin_site.register(BlockedUser, BlockedUserAdmin)
custom_admin_site.register(CustomUser, CustomUserAdmin)
