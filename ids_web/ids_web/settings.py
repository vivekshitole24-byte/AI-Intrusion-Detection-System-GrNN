from pathlib import Path
import os
from dotenv  import load_dotenv




# Load environment variables from .env file
load_dotenv()

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')

# ✅ Project Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent

# ✅ Security Keys & Debug Mode
SECRET_KEY = 'django-insecure-gd1s(l4c5w(dr556%q-kk@gse)on)*_94a_hnlr&(1$m@98j!b'
DEBUG = True
ALLOWED_HOSTS = []

# ✅ Installed Apps (Added 'ids_app')
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'ids_app',  # ✅ Ensure the name exactly matches your app folder
]




# ✅ Middleware
MIDDLEWARE = [
    'ids_app.middleware.BrokenPipeMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # ✅ Ensures CSRF protection
]

# ✅ Root URL Configuration
ROOT_URLCONF = 'ids_web.urls'

# ✅ Templates Configuration (Fixed!)
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'ids_app', 'templates')],  # ✅ Now Django finds templates
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]



# ✅ WSGI Application
WSGI_APPLICATION = 'ids_web.wsgi.application'

# ✅ Database (SQLite for now)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ✅ Password Validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ✅ Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ✅ Static Files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'ids_app', 'static')]  # ✅ Add this!

# ✅ Media Files (For user-uploaded datasets)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# ✅ Default Primary Key Type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# for ip blocking 
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your_email@gmail.com'
EMAIL_HOST_PASSWORD = 'your_email_password'


AUTH_USER_MODEL = 'ids_app.CustomUser'

CSRF_TRUSTED_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]


# ✅ Set timezone to match your actual time (e.g., India)
TIME_ZONE = 'Asia/Kolkata'  # Change this to your correct timezone

# ✅ Enable timezone-aware datetime handling
USE_TZ = True


# Ensure static files are correctly collected
STATIC_ROOT = BASE_DIR / "staticfiles"


CELERY_BROKER_URL = 'redis://localhost:6379/0'  # Using Redis
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
