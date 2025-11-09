"""
Models for Email Automation
"""
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone


class Contact(models.Model):
    """Contact/Recipient model"""
    email = models.EmailField()
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    company_name = models.CharField(max_length=200, blank=True)
    title = models.CharField(max_length=100, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        unique_together = [['email', 'created_by']]
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})" if self.first_name else self.email


class Campaign(models.Model):
    """Email campaign model"""
    name = models.CharField(max_length=200)
    subject = models.TextField()
    body = models.TextField()
    is_html = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True, help_text="Exact time when campaign finished/completed")
    status = models.CharField(
        max_length=20,
        choices=[
            ('draft', 'Draft'),
            ('sending', 'Sending'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
        ],
        default='draft'
    )
    csv_data = models.TextField(blank=True, null=True, help_text="Stored CSV recipients data as JSON")
    attributes = models.TextField(blank=True, null=True, help_text="Manual attributes from form")
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name


class EmailLog(models.Model):
    """Email sending log"""
    campaign = models.ForeignKey(Campaign, on_delete=models.SET_NULL, null=True, blank=True)
    recipient_email = models.EmailField()
    subject = models.CharField(max_length=500)
    status = models.CharField(
        max_length=20,
        choices=[
            ('sent', 'Sent'),
            ('failed', 'Failed'),
            ('bounce', 'Bounce'),
        ],
        default='sent'
    )
    error_message = models.TextField(blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-sent_at']
    
    def __str__(self):
        return f"{self.recipient_email} - {self.status}"


class BounceRecord(models.Model):
    """Record of all bounce emails found in inbox (including unmatched ones)"""
    recipient_email = models.EmailField(db_index=True)
    subject = models.CharField(max_length=500, blank=True)
    bounce_reason = models.TextField(blank=True)
    from_addr = models.CharField(max_length=500, blank=True)
    email_log = models.ForeignKey(EmailLog, on_delete=models.SET_NULL, null=True, blank=True, 
                                  help_text="Linked EmailLog entry if matched")
    detected_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['recipient_email', '-detected_at']),
        ]
    
    def __str__(self):
        return f"{self.recipient_email} - {self.detected_at}"


class UserProfile(models.Model):
    """Extended user profile with admin options"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    can_view_all_data = models.BooleanField(
        default=False,
        help_text="If enabled, user can view all data in admin. If disabled, user only sees their own data."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Profile for {self.user.username}"
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create UserProfile when User is created"""
    if created:
        UserProfile.objects.get_or_create(user=instance, defaults={'can_view_all_data': False})


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Ensure UserProfile exists when User is saved"""
    if not hasattr(instance, 'profile'):
        UserProfile.objects.get_or_create(user=instance, defaults={'can_view_all_data': False})


class UserActivity(models.Model):
    """User login/logout activity"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    activity_type = models.CharField(
        max_length=20,
        choices=[
            ('login', 'Login'),
            ('logout', 'Logout'),
        ]
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user.username} - {self.activity_type} at {self.timestamp}"


class SystemProviderSettings(models.Model):
    """System-wide default email provider settings for automated tasks"""
    provider_type = models.CharField(
        max_length=20,
        choices=[
            ('spacemail', 'SpaceMail'),
            ('gmail', 'Gmail'),
        ],
        default='spacemail'
    )
    smtp_server = models.CharField(max_length=255, default='mail.spacemail.com')
    smtp_port = models.IntegerField(default=465)
    smtp_username = models.EmailField()
    smtp_password = models.CharField(max_length=255)  # Encrypted in production
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        verbose_name = 'System Provider Settings'
        verbose_name_plural = 'System Provider Settings'
        ordering = ['-updated_at']
    
    def __str__(self):
        return f"{self.provider_type} - {self.smtp_username} ({'Active' if self.is_active else 'Inactive'})"
    
    @classmethod
    def get_active_provider(cls):
        """Get the active system provider settings"""
        return cls.objects.filter(is_active=True).first()

