import os
from celery import Celery

# Ensure Django settings module is correctly set
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ids_web.settings')

app = Celery('ids_web')

# Load task modules from all registered Django app configs
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks
app.autodiscover_tasks()
