#!/bin/bash
# Quick run script for email automation

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Please copy .env.example to .env and update values."
    exit 1
fi

# Run the email command
python manage.py send_email \
    --to natty@pdevsecops.com \
    --subject "Test Email - Python Script" \
    --body "This is a test email from the Python automation script.

Server: mail.spacemail.com
Port: 465 (SSL)" \
    --cc Natarajan@pdevsecops.com

