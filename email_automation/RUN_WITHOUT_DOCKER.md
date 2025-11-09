# Running SpaceMail Without Docker

This guide will help you run the SpaceMail email automation application directly on your system without using Docker.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## Step-by-Step Setup

### 1. Navigate to Project Directory

```bash
cd "/Users/natarajan/Documents/spacemail Automations/email_automation"
```

### 2. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables

Create a `.env` file in the `email_automation` directory (if it doesn't exist):

```bash
# Copy example if available, or create new .env file
touch .env
```

Add the following variables to your `.env` file:

```env
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000

# Database (SQLite is default, no config needed)
# For PostgreSQL, uncomment and configure:
# DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Email Settings (Optional - can be set in Django admin)
SENDER_EMAIL=your-email@example.com
SENDER_PASSWORD=your-password
```

### 5. Run Database Migrations

```bash
python manage.py migrate
```

### 6. Create Superuser (Optional - for admin access)

```bash
python manage.py createsuperuser
```

Follow the prompts to create an admin user.

### 7. Collect Static Files (if needed)

```bash
python manage.py collectstatic --noinput
```

### 8. Run Development Server

```bash
python manage.py runserver
```

The application will be available at: **http://127.0.0.1:8000/**

### 9. Access the Application

- **Main Dashboard**: http://127.0.0.1:8000/
- **Admin Panel**: http://127.0.0.1:8000/admin/
- **Send Email Page**: http://127.0.0.1:8000/send-email/

## Running on Different Port

To run on a different port (e.g., 8080):

```bash
python manage.py runserver 8080
```

## Running in Background

To run the server in the background:

```bash
# On macOS/Linux:
nohup python manage.py runserver > server.log 2>&1 &

# To stop it later:
pkill -f "python manage.py runserver"
```

## Production Setup (Using Gunicorn)

For production, use Gunicorn:

```bash
# Install gunicorn (already in requirements.txt)
pip install gunicorn

# Run with gunicorn
gunicorn config.wsgi:application --bind 0.0.0.0:8000
```

## Troubleshooting

### Port Already in Use

If port 8000 is already in use:

```bash
# Find and kill the process
lsof -ti:8000 | xargs kill -9

# Or use a different port
python manage.py runserver 8080
```

### Module Not Found Errors

Make sure your virtual environment is activated and dependencies are installed:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Database Errors

Reset the database if needed:

```bash
# Delete existing database
rm db.sqlite3

# Re-run migrations
python manage.py migrate

# Create superuser again
python manage.py createsuperuser
```

### Environment Variables Not Loading

Ensure your `.env` file is in the `email_automation` directory (same level as `manage.py`).

## Quick Start Script

You can create a simple script to automate the setup:

```bash
#!/bin/bash
# save as start.sh

cd "/Users/natarajan/Documents/spacemail Automations/email_automation"

# Activate virtual environment
source venv/bin/activate

# Run migrations (if needed)
python manage.py migrate

# Start server
python manage.py runserver
```

Make it executable:

```bash
chmod +x start.sh
./start.sh
```

## Deactivating Virtual Environment

When you're done, deactivate the virtual environment:

```bash
deactivate
```


