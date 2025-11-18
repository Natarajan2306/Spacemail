#!/usr/bin/env python
"""
Test email sending with pritam@pdsogroup.com
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
test_recipient = "Natarajan@pdevsecops.com"  # Test recipient

print("=" * 70)
print("Testing Email Sending with pritam@pdsogroup.com")
print("=" * 70)

# Step 1: Test SMTP connection
print("\n[1/2] Testing SMTP Connection...")
print(f"   Email: {test_email}")
print(f"   Server: mail.spacemail.com:465")
print()

sender = EmailSender(
    smtp_server='mail.spacemail.com',
    smtp_port=465,
    email=test_email,
    password=test_password
)

connection_result = sender.test_connection()
if connection_result['success']:
    print(f"   ✅ Connection successful!")
    print(f"   Message: {connection_result.get('message', 'OK')}")
else:
    print(f"   ❌ Connection failed!")
    print(f"   Error: {connection_result.get('error', 'Unknown error')}")
    sys.exit(1)

# Step 2: Send a test email
print(f"\n[2/2] Sending test email...")
print(f"   From: {test_email}")
print(f"   To: {test_recipient}")
print()

test_subject = "Test Email - pritam@pdsogroup.com - SpaceMail System"
test_body = f"""
This is a test email sent from the SpaceMail automation system.

Test Details:
- Sender: {test_email}
- SMTP Server: mail.spacemail.com
- Port: 465
- Recipient: {test_recipient}
- Timestamp: {django.utils.timezone.now()}

If you receive this email, the email delivery is working correctly for pdsogroup.com domain.

This test verifies:
1. SMTP authentication works
2. Email headers are properly formatted
3. Email delivery is successful
"""

try:
    success = sender.send_simple_email(
        to_email=test_recipient,
        subject=test_subject,
        body=test_body
    )
    
    if success:
        print(f"   ✅ Test email sent successfully!")
        print(f"\n   Please check {test_recipient} inbox (and spam folder)")
        print(f"   The email should arrive within a few minutes.")
    else:
        print(f"   ❌ Failed to send test email")
        print(f"   Check the logs above for details")
        
except Exception as e:
    print(f"   ❌ Error sending email: {str(e)}")
    import traceback
    print(f"\n   Full error traceback:")
    print(traceback.format_exc())

print("\n" + "=" * 70)
print("Test completed")
print("=" * 70)


