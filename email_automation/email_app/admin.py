"""
Django admin configuration
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.db.models import Q
from email_app.models import Contact, Campaign, EmailLog, UserActivity, BounceRecord, UserProfile


def can_view_all_data(user):
    """Helper function to check if user can view all data"""
    # Check profile setting first - this overrides superuser status
    if not user or not user.is_authenticated:
        return False
    try:
        # Refresh profile from database to get latest value
        profile = UserProfile.objects.get(user=user)
        return profile.can_view_all_data
    except UserProfile.DoesNotExist:
        # Create profile if it doesn't exist
        UserProfile.objects.create(user=user, can_view_all_data=False)
        return False


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile"""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fields = ('can_view_all_data',)
    help_text = "Enable 'Can view all data' to allow this user to see all data in admin. Disable to show only their own data."


class UserAdmin(BaseUserAdmin):
    """Custom User Admin with Profile"""
    inlines = (UserProfileInline,)
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_superuser', 'get_can_view_all_data')
    list_filter = ('is_staff', 'is_superuser', 'is_active')
    
    def get_can_view_all_data(self, obj):
        """Display can_view_all_data status"""
        try:
            return obj.profile.can_view_all_data
        except UserProfile.DoesNotExist:
            return False
    get_can_view_all_data.boolean = True
    get_can_view_all_data.short_description = 'Can View All Data'


# Unregister default User admin and register custom one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin for UserProfile"""
    list_display = ['user', 'can_view_all_data', 'created_at', 'updated_at']
    list_filter = ['can_view_all_data', 'created_at']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ['email', 'first_name', 'last_name', 'company_name', 'title', 'created_by', 'created_at']
    search_fields = ['email', 'first_name', 'last_name', 'company_name']
    list_filter = ['created_at', 'created_by']
    readonly_fields = ['created_at']
    
    def get_queryset(self, request):
        # Check if user can view all data - if yes, return ALL data with NO filtering
        if can_view_all_data(request.user):
            # Return completely unfiltered queryset
            return self.model.objects.all()
        # Only filter if user cannot view all data
        return super().get_queryset(request).filter(created_by=request.user)
    
    def save_model(self, request, obj, form, change):
        # Automatically set created_by to current user if not set
        if not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = ['name', 'status', 'created_by', 'created_at', 'sent_at']
    search_fields = ['name', 'subject']
    list_filter = ['status', 'created_at', 'created_by']
    readonly_fields = ['created_at', 'sent_at']
    
    def get_queryset(self, request):
        # Check if user can view all data - if yes, return ALL data with NO filtering
        if can_view_all_data(request.user):
            # Return completely unfiltered queryset
            return self.model.objects.all()
        # Only filter if user cannot view all data
        return super().get_queryset(request).filter(created_by=request.user)
    
    def save_model(self, request, obj, form, change):
        # Automatically set created_by to current user if not set
        if not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(EmailLog)
class EmailLogAdmin(admin.ModelAdmin):
    list_display = ['recipient_email', 'subject', 'status', 'sent_at', 'campaign']
    search_fields = ['recipient_email', 'subject']
    list_filter = ['status', 'sent_at', 'campaign']
    readonly_fields = ['sent_at']
    
    def get_queryset(self, request):
        # Check if user can view all data - if yes, return ALL data with NO filtering
        if can_view_all_data(request.user):
            # Return completely unfiltered queryset
            return self.model.objects.all()
        # Only filter if user cannot view all data
        return super().get_queryset(request).filter(campaign__created_by=request.user)


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ['user', 'activity_type', 'timestamp', 'ip_address']
    list_filter = ['activity_type', 'timestamp']
    readonly_fields = ['timestamp']
    search_fields = ['user__username']
    
    def get_queryset(self, request):
        # Check if user can view all data - if yes, return ALL data with NO filtering
        if can_view_all_data(request.user):
            # Return completely unfiltered queryset
            return self.model.objects.all()
        # Only filter if user cannot view all data
        return super().get_queryset(request).filter(user=request.user)


@admin.register(BounceRecord)
class BounceRecordAdmin(admin.ModelAdmin):
    list_display = ['recipient_email', 'subject', 'bounce_reason', 'detected_at', 'email_log']
    search_fields = ['recipient_email', 'subject', 'bounce_reason']
    list_filter = ['detected_at']
    readonly_fields = ['detected_at']
    
    def get_queryset(self, request):
        # Check if user can view all data - if yes, return ALL data with NO filtering
        if can_view_all_data(request.user):
            # Return completely unfiltered queryset
            return self.model.objects.all()
        # Only filter if user cannot view all data
        from email_app.models import EmailLog
        user_email_logs = EmailLog.objects.filter(campaign__created_by=request.user).values_list('recipient_email', flat=True).distinct()
        return super().get_queryset(request).filter(
            Q(email_log__campaign__created_by=request.user) |
            Q(email_log__isnull=True, recipient_email__in=user_email_logs)
        )

