from django.apps import AppConfig


class IdsAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ids_app'

    def ready(self):
        # Import signals only when apps are fully loaded
        import ids_app.signals  # ✅ Safe import inside ready()
