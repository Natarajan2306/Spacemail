# Production Setup Guide

## Why Campaigns Don't Send When Laptop Screen is Off

The issue occurs because:
1. **Django development server** (`runserver`) is not production-ready and can pause when the system sleeps
2. **Synchronous email sending** blocks the request until all emails are sent
3. **System sleep** pauses all processes, including the web server

## Solution: Use Docker with Gunicorn

We've updated the setup to use:
- **Gunicorn** (production WSGI server) instead of `runserver`
- **Docker restart policy** to keep the container running
- **Proper timeout settings** for long-running email campaigns

## Running the Server

### Option 1: Using Docker (Recommended)

```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

The container will:
- Automatically restart if it stops
- Continue running even if your laptop screen turns off
- Use Gunicorn with 4 worker processes for better performance

### Option 2: Running Gunicorn Directly (Without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Start Gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 120 config.wsgi:application
```

### Option 3: Running as a Background Service (macOS/Linux)

Create a systemd service or use `nohup`:

```bash
# Using nohup (simple)
nohup gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 120 config.wsgi:application > server.log 2>&1 &

# Or use screen/tmux
screen -S email_server
gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 120 config.wsgi:application
# Press Ctrl+A then D to detach
```

## Important Notes

1. **System Sleep**: Even with Docker/Gunicorn, if your laptop goes to sleep, the system pauses. Consider:
   - Preventing sleep: `caffeinate -d` (macOS) or `systemctl mask sleep.target` (Linux)
   - Using a cloud server or VPS for production
   - Using a Raspberry Pi or always-on device

2. **Email Sending**: Large campaigns are sent synchronously. For better performance:
   - Consider implementing Celery for async email sending
   - Use smaller batch sizes
   - Monitor server resources

3. **Timeout Settings**: Gunicorn timeout is set to 120 seconds. For very large campaigns, you may need to increase this.

## Troubleshooting

If emails still don't send when screen is off:

1. **Check if Docker is running**:
   ```bash
   docker ps
   ```

2. **Check container logs**:
   ```bash
   docker-compose logs email_automation
   ```

3. **Verify the container is running**:
   ```bash
   docker-compose ps
   ```

4. **Restart the container**:
   ```bash
   docker-compose restart
   ```

## Production Recommendations

For a production environment:
1. Deploy to a cloud server (AWS, DigitalOcean, etc.)
2. Use a process manager (systemd, supervisor)
3. Set up proper logging and monitoring
4. Implement Celery for async email sending
5. Use a reverse proxy (Nginx) in front of Gunicorn
6. Set up SSL/HTTPS

