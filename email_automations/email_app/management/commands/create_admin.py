"""
Management command to create a Django admin superuser
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from email_app.models import UserProfile


class Command(BaseCommand):
    help = 'Create a Django admin superuser with specified username and password'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            default='admin',
            help='Username for the admin user (default: admin)'
        )
        parser.add_argument(
            '--email',
            type=str,
            default='admin@example.com',
            help='Email for the admin user (default: admin@example.com)'
        )
        parser.add_argument(
            '--password',
            type=str,
            default=None,
            help='Password for the admin user (if not provided, will prompt)'
        )
        parser.add_argument(
            '--noinput',
            action='store_true',
            help='Use default password "admin123" if password not provided (for non-interactive use)'
        )

    def handle(self, *args, **options):
        username = options['username']
        email = options['email']
        password = options['password']
        noinput = options['noinput']

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'User "{username}" already exists. Skipping creation.')
            )
            user = User.objects.get(username=username)
            # Update to ensure it's a superuser
            if not user.is_superuser or not user.is_staff:
                user.is_superuser = True
                user.is_staff = True
                user.save()
                self.stdout.write(
                    self.style.SUCCESS(f'Updated user "{username}" to be a superuser.')
                )
            return

        # Get password
        if not password:
            if noinput:
                password = 'admin123'
                self.stdout.write(
                    self.style.WARNING('Using default password "admin123" (use --password to set custom password)')
                )
            else:
                from getpass import getpass
                password = getpass('Enter password for admin user: ')
                password_confirm = getpass('Confirm password: ')
                if password != password_confirm:
                    self.stdout.write(
                        self.style.ERROR('Passwords do not match. User creation cancelled.')
                    )
                    return
                if len(password) < 8:
                    self.stdout.write(
                        self.style.ERROR('Password must be at least 8 characters long. User creation cancelled.')
                    )
                    return

        # Create superuser
        try:
            user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password
            )
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created superuser "{username}"')
            )
            
            # Create user profile
            UserProfile.objects.get_or_create(
                user=user,
                defaults={'can_view_all_data': True}
            )
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created user profile for "{username}"')
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'\nAdmin user created successfully!')
            )
            self.stdout.write(f'Username: {username}')
            self.stdout.write(f'Email: {email}')
            self.stdout.write(f'Password: {"*" * len(password)}')
            self.stdout.write(f'\nYou can now login to Django admin at: /admin/')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating superuser: {str(e)}')
            )

