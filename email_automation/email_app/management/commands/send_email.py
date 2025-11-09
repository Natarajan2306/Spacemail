"""
Django management command to send emails
"""
from django.core.management.base import BaseCommand
from email_app.services import EmailSender


class Command(BaseCommand):
    help = 'Send email using the EmailSender service'

    def add_arguments(self, parser):
        parser.add_argument(
            '--to',
            type=str,
            required=True,
            help='Recipient email address',
        )
        parser.add_argument(
            '--subject',
            type=str,
            required=True,
            help='Email subject',
        )
        parser.add_argument(
            '--body',
            type=str,
            required=True,
            help='Email body content',
        )
        parser.add_argument(
            '--cc',
            type=str,
            nargs='+',
            help='CC email addresses (space-separated)',
        )
        parser.add_argument(
            '--html',
            action='store_true',
            help='Send as HTML email',
        )

    def handle(self, *args, **options):
        sender = EmailSender()
        
        to_email = options['to']
        subject = options['subject']
        body = options['body']
        cc = options.get('cc', None)
        is_html = options.get('html', False)
        
        self.stdout.write(f"Sending email to {to_email}...")
        
        if is_html:
            success = sender.send_html_email(
                to_email=to_email,
                subject=subject,
                html_body=body,
                cc=cc
            )
        else:
            success = sender.send_simple_email(
                to_email=to_email,
                subject=subject,
                body=body,
                cc=cc
            )
        
        if success:
            self.stdout.write(self.style.SUCCESS('Email sent successfully!'))
        else:
            self.stdout.write(self.style.ERROR('Failed to send email!'))

