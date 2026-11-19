try:
    from .celery import app as celery_app
    __all__ = ('celery_app',)
except ImportError:
    # Celery is optional — the app runs fine without it (no background tasks)
    celery_app = None
    __all__ = ()