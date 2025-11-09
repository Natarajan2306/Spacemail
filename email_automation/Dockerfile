FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Django Settings
ENV SECRET_KEY=django-insecure-change-this-in-production
ENV DEBUG=True
ENV ALLOWED_HOSTS=localhost,127.0.0.1,spacemail.pdevsecops.com

# Email Settings (SpaceMail) - Defaults
ENV SMTP_SERVER=mail.spacemail.com
ENV SMTP_PORT=465
ENV SENDER_EMAIL=natty@pdsolearn.com

# IMAP Settings for Bounce Detection
ENV IMAP_SERVER=mail.spacemail.com
ENV IMAP_PORT=993

# Gmail Settings (optional)
ENV GMAIL_CLIENT_ID=
ENV GMAIL_CLIENT_SECRET=
ENV GMAIL_REFRESH_TOKEN=
ENV GMAIL_ACCESS_TOKEN=

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . /app/

# Collect static files
RUN python manage.py collectstatic --noinput || true

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose port (if needed for web interface)
EXPOSE 8000

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command - run Gunicorn production server
# Reduced workers to 2 to prevent memory issues, increased timeout for long email campaigns
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "2", "--timeout", "300", "--keep-alive", "5", "--max-requests", "1000", "--max-requests-jitter", "100", "--worker-class", "sync", "config.wsgi:application"]

