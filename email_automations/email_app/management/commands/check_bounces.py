"""
Management command to check for email bounces
Usage: python manage.py check_bounces
"""
from django.core.management.base import BaseCommand
from email_app.bounce_detector import BounceDetector


class Command(BaseCommand):
    help = 'Check for email bounces and update EmailLog status'

    def add_arguments(self, parser):
        parser.add_argument(
            '--mailbox',
            type=str,
            default='INBOX',
            help='Mailbox to check (default: INBOX)'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=50,
            help='Maximum number of emails to check (default: 50)'
        )

    def handle(self, *args, **options):
        mailbox = options['mailbox']
        limit = options['limit']
        
        self.stdout.write('🔍 Starting bounce detection...')
        
        detector = BounceDetector()
        bounces = detector.check_bounces(mailbox=mailbox, limit=limit)
        
        if bounces:
            self.stdout.write(f'\n📬 Found {len(bounces)} bounce(s)')
            result = detector.update_bounce_status(bounces)
            
            self.stdout.write(self.style.SUCCESS(
                f'\n✅ Bounce Detection Complete:'
                f'\n   - Bounces found: {result["total_bounces"]}'
                f'\n   - Status updated: {result["updated"]}'
                f'\n   - Not found in EmailLog: {result["not_found"]}'
            ))
        else:
            self.stdout.write(self.style.SUCCESS('✅ No bounces detected'))

