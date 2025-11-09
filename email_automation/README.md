# Email Automation Django Project

Django-based email automation system for Practical DevSecOps with Docker support.

## Features

- Send simple text emails
- Send HTML emails
- Send emails with attachments
- Bulk email campaigns
- Threaded email support
- Docker containerization

## Setup

### 1. Environment Variables

Copy `.env.example` to `.env` and update the values:

```bash
cp .env.example .env
```

Edit `.env` with your SMTP credentials:
```
SMTP_SERVER=mail.spacemail.com
SMTP_PORT=465
SENDER_EMAIL=your-email@example.com
SENDER_PASSWORD=your-password
```

### 2. Using Docker (Recommended)

Build and run with Docker Compose:

```bash
docker-compose build
docker-compose up
```

Or run a one-time email send:

```bash
docker-compose run --rm email_automation python manage.py send_email \
  --to natty@pdevsecops.com \
  --subject "Test Email" \
  --body "This is a test email" \
  --cc Natarajan@pdevsecops.com
```

### 3. Local Development

Install dependencies:

```bash
pip install -r requirements.txt
```

Run migrations:

```bash
python manage.py migrate
```

Send an email:

```bash
python manage.py send_email \
  --to natty@pdevsecops.com \
  --subject "Test Email" \
  --body "This is a test email" \
  --cc Natarajan@pdevsecops.com
```

Send HTML email:

```bash
python manage.py send_email \
  --to natty@pdevsecops.com \
  --subject "HTML Email" \
  --body "<h1>Hello</h1><p>This is HTML</p>" \
  --html
```

## Usage

### Management Command

```bash
python manage.py send_email \
  --to recipient@example.com \
  --subject "Email Subject" \
  --body "Email body content" \
  --cc cc1@example.com cc2@example.com \
  --html  # Optional: for HTML emails
```

### Python Code

```python
from email_app.services import EmailSender

sender = EmailSender()

# Send simple email
sender.send_simple_email(
    to_email='natty@pdevsecops.com',
    subject='Test Email',
    body='Email body',
    cc=['Natarajan@pdevsecops.com']
)

# Send HTML email
sender.send_html_email(
    to_email='natty@pdevsecops.com',
    subject='HTML Email',
    html_body='<h1>Hello</h1>',
    cc=['Natarajan@pdevsecops.com']
)
```

## Project Structure

```
email_automation/
├── config/              # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── email_app/           # Email application
│   ├── services.py      # EmailSender class
│   └── management/
│       └── commands/
│           └── send_email.py
├── manage.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## Docker Commands

Build image:
```bash
docker-compose build
```

Run container:
```bash
docker-compose up
```

Run one-time command:
```bash
docker-compose run --rm email_automation python manage.py send_email --to test@example.com --subject "Test" --body "Body"
```

View logs:
```bash
docker-compose logs -f
```

Stop container:
```bash
docker-compose down
```

