"""
Django management command to test email sending with pritam@pdsogroup.com
"""
from django.core.management.base import BaseCommand
from email_app.services import EmailSender


class Command(BaseCommand):
    help = 'Test email sending with pritam@pdsogroup.com credentials'

    def add_arguments(self, parser):
        parser.add_argument(
            '--to',
            type=str,
            default='Natarajan@pdevsecops.com',
            help='Recipient email address (default: Natarajan@pdevsecops.com)'
        )

    def handle(self, *args, **options):
        test_email = "pritam@pdsogroup.com"
        test_password = "t0XaHb@R7a2##MPn"
        recipient = options['to']

        self.stdout.write("=" * 60)
        self.stdout.write(self.style.SUCCESS("Testing Email Sending with pritam@pdsogroup.com"))
        self.stdout.write("=" * 60)

        # Step 1: Test SMTP connection
        self.stdout.write("\n1. Testing SMTP Connection...")
        sender = EmailSender(
            smtp_server='mail.spacemail.com',
            smtp_port=465,
            email=test_email,
            password=test_password
        )

        connection_result = sender.test_connection()
        if connection_result['success']:
            self.stdout.write(self.style.SUCCESS(f"   ✅ Connection successful: {connection_result.get('message', 'OK')}"))
        else:
            self.stdout.write(self.style.ERROR(f"   ❌ Connection failed: {connection_result.get('error', 'Unknown error')}"))
            return

        # Step 2: Send a test email
        self.stdout.write(f"\n2. Sending test email to {recipient}...")
        self.stdout.write(f"   From: {test_email}")

        test_subject = "Test Email from SpaceMail - pritam@pdsogroup.com"
        test_body = f"""
This is a test email sent from the SpaceMail automation system.

Test Details:
- Sender: {test_email}
- SMTP Server: mail.spacemail.com
- Port: 465
- Recipient: {recipient}

If you receive this email, the email delivery is working correctly.
"""

        try:
            success = sender.send_simple_email(
                to_email=recipient,
                subject=test_subject,
                body=test_body
            )

            if success:
                self.stdout.write(self.style.SUCCESS(f"\n✅ Test email sent successfully!"))
                self.stdout.write(f"   Please check {recipient} inbox (and spam folder)")
            else:
                self.stdout.write(self.style.ERROR(f"\n❌ Failed to send test email"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"\n❌ Error sending email: {str(e)}"))
            import traceback
            self.stdout.write(traceback.format_exc())

        self.stdout.write("\n" + "=" * 60)
        self.stdout.write("Test completed")
        self.stdout.write("=" * 60)


