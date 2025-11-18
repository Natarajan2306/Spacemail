#!/usr/bin/env python
"""
Test script to verify email sending with pritam@pdsogroup.com
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from email_app.services import EmailSender

# Test credentials
test_email = "pritam@pdsogroup.com"
test_password = "t0XaHb@R7a2##MPn"
test_recipient = "Natarajan@pdevsecops.com"  # Using the email from logs

print("=" * 60)
print("Testing Email Sending with pritam@pdsogroup.com")
print("=" * 60)

# Step 1: Test SMTP connection
print("\n1. Testing SMTP Connection...")
sender = EmailSender(
    smtp_server='mail.spacemail.com',
    smtp_port=465,
    email=test_email,
    password=test_password
)

connection_result = sender.test_connection()
print(f"   Connection Result: {connection_result}")

if not connection_result['success']:
    print(f"\n❌ Connection failed: {connection_result.get('error', 'Unknown error')}")
    sys.exit(1)

print("\n✅ SMTP Connection successful!")

# Step 2: Send a test email
print(f"\n2. Sending test email to {test_recipient}...")
print(f"   From: {test_email}")

test_subject = "Test Email from SpaceMail - pritam@pdsogroup.com"
test_body = """
This is a test email sent from the SpaceMail automation system.

Test Details:
- Sender: pritam@pdsogroup.com
- SMTP Server: mail.spacemail.com
- Port: 465

If you receive this email, the email delivery is working correctly.
"""

try:
    success = sender.send_simple_email(
        to_email=test_recipient,
        subject=test_subject,
        body=test_body
    )
    
    if success:
        print(f"\n✅ Test email sent successfully!")
        print(f"   Please check {test_recipient} inbox (and spam folder)")
    else:
        print(f"\n❌ Failed to send test email")
        
except Exception as e:
    print(f"\n❌ Error sending email: {str(e)}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("Test completed")
print("=" * 60)


