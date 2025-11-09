#!/bin/bash
set -e

# Run migrations
python manage.py migrate --noinput

# Execute the command passed to the container
exec "$@"

