#!/bin/bash
# Script to create a Django admin user
# Usage: ./create_admin_user.sh [username] [email] [password]

cd "$(dirname "$0")"

# Default values
USERNAME=${1:-admin}
EMAIL=${2:-admin@example.com}
PASSWORD=${3:-admin123}

echo "Creating Django admin user..."
echo "Username: $USERNAME"
echo "Email: $EMAIL"
echo "Password: $PASSWORD"
echo ""

python manage.py create_admin --username "$USERNAME" --email "$EMAIL" --password "$PASSWORD" --noinput

echo ""
echo "Admin user created successfully!"
echo "You can now login to Django admin at: http://localhost:8000/admin/"
echo "Username: $USERNAME"
echo "Password: $PASSWORD"

