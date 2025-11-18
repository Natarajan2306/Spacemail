#!/bin/bash
set -e

# Run migrations
python manage.py migrate --noinput

# Create or update default admin users
python manage.py shell << 'PYEOF'
from django.contrib.auth.models import User
from email_app.models import UserProfile

# List of default admin users
default_users = [
    {
        'username': 'natarajan',
        'password': 'natarajan123',
        'email': 'natty@pdevsecops.com',
        'can_view_all_data': True  # Only natarajan can view all data
    },
    {
        'username': 'payal',
        'password': 'Paya@123',
        'email': 'Payal@pdevsecops.com',
        'can_view_all_data': False  # Payal can only view own data
    },
    {
        'username': 'pritam',
        'password': 'Pritam@123',
        'email': 'pritam@pdevsecops.com',
        'can_view_all_data': False  # Pritam can only view own data
    }
]

# Create or update each user
for user_data in default_users:
    username = user_data['username']
    password = user_data['password']
    email = user_data['email']
    can_view_all = user_data['can_view_all_data']
    
    try:
        user = User.objects.get(username=username)
        # Update password and ensure admin privileges
        user.set_password(password)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        if email:
            user.email = email
        user.save()
        print(f'✓ Updated admin user "{username}" with default password')
    except User.DoesNotExist:
        # Create new admin user
        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password
        )
        print(f'✓ Created admin user "{username}" with default password')
    
    # Ensure UserProfile exists with correct permissions
    try:
        profile = UserProfile.objects.get(user=user)
        profile.can_view_all_data = can_view_all
        profile.save()
        if can_view_all:
            print(f'✓ Updated user profile for "{username}" - can view all data')
        else:
            print(f'✓ Updated user profile for "{username}" - can only view own data')
    except UserProfile.DoesNotExist:
        UserProfile.objects.create(user=user, can_view_all_data=can_view_all)
        if can_view_all:
            print(f'✓ Created user profile for "{username}" - can view all data')
        else:
            print(f'✓ Created user profile for "{username}" - can only view own data')
PYEOF

# Execute the command passed to the container
exec "$@"
