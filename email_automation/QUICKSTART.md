# Quick Start Guide

## Important: Make sure you're in the correct directory!

```bash
cd "/Users/natarajan/Documents/spacemail Automations/email_automation"
```

## Option 1: Test Locally (No Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Send email
python manage.py send_email \
  --to natty@pdevsecops.com \
  --subject "Test Email" \
  --body "This is a test email" \
  --cc Natarajan@pdevsecops.com
```

## Option 2: Using Docker

```bash
# Make sure you're in the email_automation directory
cd "/Users/natarajan/Documents/spacemail Automations/email_automation"

# Build the image (first time only, or after changes)
docker-compose build

# Run and send email
docker-compose up

# Or run with custom command
docker-compose run --rm email_automation python manage.py send_email \
  --to natty@pdevsecops.com \
  --subject "Custom Subject" \
  --body "Custom body" \
  --cc Natarajan@pdevsecops.com
```

## Troubleshooting

### Port 5432 Error
If you see a port 5432 error, you're likely in the wrong directory or running a different project's docker-compose. Make sure you're in the `email_automation` directory.

### Check Current Directory
```bash
pwd
# Should show: /Users/natarajan/Documents/spacemail Automations/email_automation
```

### Verify Docker Compose File
```bash
ls docker-compose.yml
# Should show the file exists
```

## Quick Test Script

```bash
./run.sh
```

