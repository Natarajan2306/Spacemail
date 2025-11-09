# Email Automation Setup Guide

## Initial Setup

### 1. Create Database Tables

Run migrations to create the database tables:

```bash
python manage.py makemigrations
python manage.py migrate
```

### 2. Create Superuser

Create a Django superuser account for login:

```bash
python manage.py createsuperuser
```

Enter:
- Username: (your choice)
- Email: (optional)
- Password: (your choice)

### 3. Run the Server

```bash
python manage.py runserver
```

Or with Docker:

```bash
docker-compose up
```

## Access the Application

1. **Login**: Go to `http://localhost:8000/login/`
   - Use the superuser credentials you created

2. **Dashboard**: After login, you'll see:
   - Total Emails in database
   - Campaigns Sent count
   - Total Contacts
   - Last Login/Logout timing

3. **Send Email**: Click "Send Email" in the navigation to access the email form

## Features

- ✅ Dashboard with statistics
- ✅ Login/Logout with activity tracking
- ✅ Send single or bulk emails
- ✅ CSV upload with automatic attribute detection
- ✅ Email attachments
- ✅ Personalized attributes
- ✅ Campaign tracking
- ✅ Contact management

## Database Models

- **Contact**: Stores recipient information
- **Campaign**: Tracks email campaigns
- **EmailLog**: Logs all sent emails
- **UserActivity**: Tracks login/logout activities

