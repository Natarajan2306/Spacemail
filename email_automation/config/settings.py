"""
Django settings for email_automation project.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-change-this-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'True') == 'True'

# ALLOWED_HOSTS - always include Render domain even if set via env var
allowed_hosts_default = 'localhost,127.0.0.1,spacemail.pdevsecops.com,spacemail-u779.onrender.com'
allowed_hosts_env = os.getenv('ALLOWED_HOSTS', allowed_hosts_default)

# Parse and clean hosts
if allowed_hosts_env:
    ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',') if host.strip()]
else:
    ALLOWED_HOSTS = []

# Always ensure Render domain is included (case-insensitive check)
render_domain = 'spacemail-u779.onrender.com'
if not any(host.lower() == render_domain.lower() for host in ALLOWED_HOSTS):
    ALLOWED_HOSTS.append(render_domain)

# Ensure we have at least the default hosts if list is empty
if not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'spacemail.pdevsecops.com', render_domain]

# CSRF Settings
csrf_origins_env = os.getenv('CSRF_TRUSTED_ORIGINS', '')
if csrf_origins_env:
    # Filter out empty strings and ensure all entries have a scheme
    CSRF_TRUSTED_ORIGINS = [
        origin.strip() 
        for origin in csrf_origins_env.split(',') 
        if origin.strip() and (origin.strip().startswith('http://') or origin.strip().startswith('https://'))
    ]
    # If filtering removed all entries, use defaults
    if not CSRF_TRUSTED_ORIGINS:
        CSRF_TRUSTED_ORIGINS = ['http://localhost:8002', 'http://127.0.0.1:8002', 'https://spacemail-u779.onrender.com']
else:
    CSRF_TRUSTED_ORIGINS = ['http://localhost:8002', 'http://127.0.0.1:8002', 'https://spacemail-u779.onrender.com']
CSRF_COOKIE_SECURE = False  # Set to True in production with HTTPS
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
# Session configuration - ensure each user has independent sessions
SESSION_COOKIE_NAME = 'sessionid'  # Default session cookie name
SESSION_COOKIE_AGE = 1209600  # 2 weeks in seconds
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
SESSION_SAVE_EVERY_REQUEST = False  # Only save session when modified
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Session persists after browser close
# Ensure sessions are stored in database (not shared cache)
SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'email_app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'config.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

STATICFILES_DIRS = [
    BASE_DIR / 'email_app' / 'static',
]

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email Configuration
# Required environment variables for production (set these in Render):
# - SMTP_SERVER: Your SMTP server (default: mail.spacemail.com)
# - SMTP_PORT: SMTP port, usually 465 for SSL (default: 465)
# - SENDER_EMAIL: Your email address for sending emails
# - SENDER_PASSWORD: Your email password or app-specific password
#
# Note: Render free tier has a 30-second request timeout. SMTP connections are optimized
# to complete within this limit. If you experience timeouts, check:
# 1. Network connectivity from Render to your SMTP server
# 2. Firewall rules allowing outbound connections on port 465
# 3. SMTP server response time (should be < 15 seconds)
SMTP_SERVER = os.getenv('SMTP_SERVER', 'mail.spacemail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '465'))
SENDER_EMAIL = os.getenv('SENDER_EMAIL', 'natty@pdsolearn.com')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD', '')

# IMAP Configuration for Bounce Detection
IMAP_SERVER = os.getenv('IMAP_SERVER', 'mail.spacemail.com')  # Usually same as SMTP server
IMAP_PORT = int(os.getenv('IMAP_PORT', '993'))  # SSL port for IMAP

# Login URL
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

