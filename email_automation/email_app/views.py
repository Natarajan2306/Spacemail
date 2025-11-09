"""
Views for email automation web interface
"""
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import json
import csv
import os
import tempfile
import time
from email_app.services import EmailSender, load_recipients_from_csv
from email_app.models import Contact, Campaign, EmailLog, UserActivity, BounceRecord, UserProfile


def can_view_all_data(user):
    """Helper function to check if user can view all data in frontend"""
    if not user or not user.is_authenticated:
        return False
    try:
        # Refresh profile from database to get latest value
        profile = UserProfile.objects.get(user=user)
        return profile.can_view_all_data
    except UserProfile.DoesNotExist:
        # Create profile if it doesn't exist
        UserProfile.objects.get_or_create(user=user, defaults={'can_view_all_data': False})
        return False


def login_view(request):
    """User login"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            # Do not automatically grant admin privileges - only users marked as admin in Django admin will have admin access
            # Create user profile if it doesn't exist
            UserProfile.objects.get_or_create(user=user, defaults={'can_view_all_data': False})
            login(request, user)
            # Log login activity
            UserActivity.objects.create(
                user=user,
                activity_type='login',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return redirect('dashboard')
        else:
            return render(request, 'email_app/login.html', {'error': 'Invalid credentials'})
    
    return render(request, 'email_app/login.html')


def logout_view(request):
    """User logout - Only logs out the current user, does not affect other users"""
    if request.user.is_authenticated:
        # Store user info before logout for logging
        user = request.user
        ip_address = request.META.get('REMOTE_ADDR')
        
        # Log logout activity before clearing session
        UserActivity.objects.create(
            user=user,
            activity_type='logout',
            ip_address=ip_address
        )
        
        # Clear only this user's session (Django's logout() handles this correctly)
        # This will only affect the current request's session, not other users
        logout(request)
        
        # Explicitly flush session to ensure it's cleared
        request.session.flush()
    return redirect('login')


def signup_view(request):
    """User signup"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    error_message = None
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        
        # Validation
        if not username or not email or not password:
            error_message = 'All fields are required'
        elif password != password_confirm:
            error_message = 'Passwords do not match'
        elif len(password) < 8:
            error_message = 'Password must be at least 8 characters long'
        elif User.objects.filter(username=username).exists():
            error_message = 'Username already exists'
        elif User.objects.filter(email=email).exists():
            error_message = 'Email already exists'
        else:
            # Create user
            try:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                # is_staff and is_superuser default to False - can be set manually in Django admin if needed
                # Create user profile if it doesn't exist
                UserProfile.objects.get_or_create(user=user, defaults={'can_view_all_data': False})
                # Log in the user
                login(request, user)
                # Log login activity
                UserActivity.objects.create(
                    user=user,
                    activity_type='login',
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                return redirect('dashboard')
            except Exception as e:
                error_message = f'Error creating account: {str(e)}'
    
    return render(request, 'email_app/signup.html', {'error': error_message})


def get_dashboard_data(user, view_all=None, filter_by_user=False):
    """Helper function to get dashboard data
    Args:
        user: The user whose data to show (selected_user or request.user)
        view_all: Whether the logged-in user can view all data (if None, checks user's permissions)
        filter_by_user: If True, always filter by user (even if view_all is True). Used when admin selects a specific user.
    """
    # Check if logged-in user can view all data (use provided view_all or check user's permissions)
    if view_all is None:
        view_all = can_view_all_data(user)
    
    # Determine if we should filter by user
    # If filter_by_user is True, or if view_all is False, filter by user
    should_filter_by_user = filter_by_user or not view_all
    
    # Get statistics - filter by user or show all
    if should_filter_by_user:
        total_emails = EmailLog.objects.filter(campaign__created_by=user).count()
        total_campaigns = Campaign.objects.filter(created_by=user).count()
        total_contacts = Contact.objects.filter(created_by=user).count()
        campaigns_sent = Campaign.objects.filter(created_by=user, status='completed').count()
    else:
        total_emails = EmailLog.objects.all().count()
        total_campaigns = Campaign.objects.all().count()
        total_contacts = Contact.objects.all().count()
        campaigns_sent = Campaign.objects.filter(status='completed').count()
    
    # Get recent login/logout activities
    if view_all:
        recent_activities = UserActivity.objects.all().order_by('-timestamp')[:10]
    else:
        recent_activities = UserActivity.objects.filter(user=user).order_by('-timestamp')[:10]
    
    # Get last login
    if view_all:
        last_login_activity = UserActivity.objects.filter(activity_type='login').order_by('-timestamp').first()
    else:
        last_login_activity = UserActivity.objects.filter(
            user=user,
            activity_type='login'
        ).order_by('-timestamp').first()
    
    # Get last logout
    if view_all:
        last_logout_activity = UserActivity.objects.filter(activity_type='logout').order_by('-timestamp').first()
    else:
        last_logout_activity = UserActivity.objects.filter(
            user=user,
            activity_type='logout'
        ).order_by('-timestamp').first()
    
    # Recent campaigns with duration calculation
    if view_all:
        recent_campaigns = Campaign.objects.all().order_by('-created_at')[:5]
    else:
        recent_campaigns = Campaign.objects.filter(created_by=user).order_by('-created_at')[:5]
    # Add duration to each campaign
    from django.utils import timezone
    now = timezone.now()
    for campaign in recent_campaigns:
        if campaign.completed_at:
            # Campaign is completed - show total duration
            start_time = campaign.sent_at if campaign.sent_at else campaign.created_at
            duration = campaign.completed_at - start_time
            total_seconds = int(duration.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            if hours > 0:
                campaign.duration_str = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                campaign.duration_str = f"{minutes}m {seconds}s"
            else:
                campaign.duration_str = f"{seconds}s"
            campaign.elapsed_str = None
        elif campaign.status == 'sending':
            # Campaign is currently sending - show elapsed time
            # Use sent_at if available, otherwise use created_at
            start_time = campaign.sent_at if campaign.sent_at else campaign.created_at
            elapsed = now - start_time
            total_seconds = int(elapsed.total_seconds())
            # Ensure non-negative
            if total_seconds < 0:
                total_seconds = 0
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            if hours > 0:
                campaign.elapsed_str = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                campaign.elapsed_str = f"{minutes}m {seconds}s"
            else:
                campaign.elapsed_str = f"{seconds}s"
            campaign.duration_str = None
            # Store start time ISO for client-side updates
            campaign.start_time_iso = start_time.isoformat()
        else:
            campaign.duration_str = None
            campaign.elapsed_str = None
    
    # Recent emails with contact information
    if view_all:
        recent_emails = EmailLog.objects.select_related('campaign').all().order_by('-sent_at')[:10]
    else:
        recent_emails = EmailLog.objects.select_related('campaign').filter(campaign__created_by=user).order_by('-sent_at')[:10]
    
    # Get contacts for recent emails and create email data list
    email_addresses = [email.recipient_email for email in recent_emails if email.recipient_email]
    # Use case-insensitive lookup for contacts
    contacts_dict = {}
    if email_addresses:
        # Get all contacts and create a case-insensitive lookup
        if view_all:
            all_contacts = Contact.objects.filter(email__in=email_addresses)
        else:
            all_contacts = Contact.objects.filter(created_by=user, email__in=email_addresses)
        for contact in all_contacts:
            # Store with lowercase email as key for case-insensitive matching
            contacts_dict[contact.email.lower()] = contact
        # Also create reverse lookup by original email
        for email_addr in email_addresses:
            if email_addr.lower() in contacts_dict:
                contacts_dict[email_addr] = contacts_dict[email_addr.lower()]
    
    # Prepare email data for export - also try to get first name from campaign CSV data
    recent_emails_data = []
    for email in recent_emails:
        # Try case-insensitive lookup
        contact = contacts_dict.get(email.recipient_email) or contacts_dict.get(email.recipient_email.lower() if email.recipient_email else '')
        
        # If no contact or no first name, try to get from campaign CSV data
        first_name_from_csv = ''
        if email.campaign and (not contact or not contact.first_name):
            if email.campaign.csv_data:
                try:
                    csv_recipients = json.loads(email.campaign.csv_data)
                    # Find matching recipient by email
                    for recipient in csv_recipients:
                        recipient_email = None
                        for key in ['email', 'Email', 'EMAIL', 'e-mail', 'E-mail', 'E-Mail']:
                            if key in recipient and recipient[key]:
                                recipient_email = recipient[key].strip().lower()
                                break
                        
                        if recipient_email and email.recipient_email and recipient_email == email.recipient_email.lower():
                            # Found matching recipient - extract first name
                            first_name_from_csv = (recipient.get('First Name') or 
                                         recipient.get('first_name') or 
                                         recipient.get('FirstName') or
                                         recipient.get('first name') or
                                         recipient.get('FIRST NAME') or
                                         recipient.get('name') or
                                         recipient.get('Name') or '')
                            
                            print(f"DEBUG: Found CSV recipient for {email.recipient_email}, first_name_from_csv='{first_name_from_csv}', recipient keys: {list(recipient.keys())}")
                            
                            # If we found first name from CSV, create or update contact
                            if first_name_from_csv:
                                if not contact:
                                    contact, _ = Contact.objects.get_or_create(
                                        email=email.recipient_email,
                                        created_by=user,
                                        defaults={'first_name': first_name_from_csv}
                                    )
                                    # Update contacts_dict so it's available for this request
                                    contacts_dict[email.recipient_email.lower()] = contact
                                    if email.recipient_email != email.recipient_email.lower():
                                        contacts_dict[email.recipient_email] = contact
                                elif not contact.first_name:
                                    contact.first_name = first_name_from_csv
                                    contact.save()
                            break
                except Exception as e:
                    print(f"Error parsing CSV data for campaign {email.campaign.id}: {str(e)}")
        
        # If contact exists but no first name, use CSV first name
        if contact and not contact.first_name and first_name_from_csv:
            contact.first_name = first_name_from_csv
            contact.save()
        
        # If no contact but we have first name from CSV, create one
        if not contact and first_name_from_csv:
            contact, _ = Contact.objects.get_or_create(
                email=email.recipient_email,
                created_by=user,
                defaults={'first_name': first_name_from_csv}
            )
            # Update contacts_dict for this request
            contacts_dict[email.recipient_email.lower()] = contact
            if email.recipient_email != email.recipient_email.lower():
                contacts_dict[email.recipient_email] = contact
        elif contact and not contact.first_name and first_name_from_csv:
            # Update contact object - set in memory and save
            contact.first_name = first_name_from_csv
            contact.save()
        
        recent_emails_data.append({
            'email': email,
            'contact': contact
        })
        # Debug: log contact status
        if email.recipient_email:
            if contact:
                print(f"DEBUG: Email {email.recipient_email} - Contact found, first_name='{contact.first_name if hasattr(contact, 'first_name') else 'N/A'}'")
            else:
                print(f"DEBUG: Email {email.recipient_email} - No contact found, first_name_from_csv='{first_name_from_csv}'")
    
    # Active campaigns (sending or draft)
    if view_all:
        active_campaigns = Campaign.objects.filter(status__in=['sending', 'draft']).count()
    else:
        active_campaigns = Campaign.objects.filter(created_by=user, status__in=['sending', 'draft']).count()
    
    # Failed emails
    if should_filter_by_user:
        failed_emails = EmailLog.objects.filter(campaign__created_by=user, status='failed').count()
        sent_emails = EmailLog.objects.filter(campaign__created_by=user, status='sent').count()
    else:
        failed_emails = EmailLog.objects.filter(status='failed').count()
        sent_emails = EmailLog.objects.filter(status='sent').count()
    
    # Bounce emails: count ALL bounce emails to display (EmailLog bounces + unmatched BounceRecord entries)
    try:
        from datetime import timedelta
        recent_cutoff = timezone.now() - timedelta(days=30)
        if should_filter_by_user:
            # Count EmailLog bounces - filter by user's campaigns
            email_log_bounces = EmailLog.objects.filter(campaign__created_by=user, status='bounce').count()
            # Count unmatched bounces from BounceRecord (not in EmailLog) - filter by user's campaigns
            user_email_logs = EmailLog.objects.filter(campaign__created_by=user).values_list('recipient_email', flat=True).distinct()
            unmatched_bounces = BounceRecord.objects.filter(
                email_log__isnull=True,
                recipient_email__in=user_email_logs,
                detected_at__gte=recent_cutoff
            ).count()
            bounce_emails = email_log_bounces + unmatched_bounces
        else:
            # Count all EmailLog bounces
            email_log_bounces = EmailLog.objects.filter(status='bounce').count()
            # Count all unmatched bounces
            unmatched_bounces = BounceRecord.objects.filter(
                email_log__isnull=True,
                detected_at__gte=recent_cutoff
            ).count()
            bounce_emails = email_log_bounces + unmatched_bounces
    except Exception:
        # Fallback to EmailLog if BounceRecord doesn't exist yet (migration not run)
        if should_filter_by_user:
            bounce_emails = EmailLog.objects.filter(campaign__created_by=user, status='bounce').count()
        else:
            bounce_emails = EmailLog.objects.filter(status='bounce').count()
    
    return {
        'total_emails': total_emails,
        'total_campaigns': total_campaigns,
        'campaigns_sent': campaigns_sent,
        'active_campaigns': active_campaigns,
        'total_contacts': total_contacts,
        'recent_activities': recent_activities,
        'last_login': last_login_activity,
        'last_logout': last_logout_activity,
        'recent_campaigns': recent_campaigns,
        'recent_emails': recent_emails,
        'recent_emails_data': recent_emails_data,
        'sent_emails': sent_emails,
        'failed_emails': failed_emails,
        'bounce_emails': bounce_emails,
    }
    

@login_required
def dashboard(request):
    """Dashboard with statistics"""
    # Check if user can view all data - if yes, show user selector
    view_all = can_view_all_data(request.user)
    selected_user_id = request.GET.get('user_id', None)
    selected_user = None
    
    if view_all and selected_user_id:
        try:
            selected_user = User.objects.get(id=selected_user_id)
        except User.DoesNotExist:
            selected_user = request.user
    else:
        selected_user = request.user
    
    # If admin selected a specific user, filter by that user
    filter_by_user = view_all and selected_user_id is not None
    context = get_dashboard_data(selected_user, view_all=view_all, filter_by_user=filter_by_user)
    context['view_all'] = view_all
    context['selected_user'] = selected_user
    return render(request, 'email_app/dashboard_tailadmin.html', context)


@login_required
@csrf_exempt
def get_users_api(request):
    """API endpoint to get all users for dropdown"""
    try:
        view_all = can_view_all_data(request.user)
        if not view_all:
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to view all users'
            }, status=403)
        
        users = User.objects.all().order_by('username')
        users_data = [{
            'id': user.id,
            'username': user.username,
            'email': user.email or '',
            'is_current': user.id == request.user.id,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser
        } for user in users]
        
        return JsonResponse({
            'success': True,
            'users': users_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
def dashboard_api(request):
    """API endpoint to get dashboard data as JSON"""
    try:
        # Check if user can view all data and if a specific user is selected
        view_all = can_view_all_data(request.user)
        selected_user_id = request.GET.get('user_id', None)
        selected_user = None
        
        if view_all and selected_user_id:
            try:
                selected_user = User.objects.get(id=selected_user_id)
            except User.DoesNotExist:
                selected_user = request.user
        else:
            selected_user = request.user
        
        view_all = can_view_all_data(request.user)
        # If admin selected a specific user, filter by that user
        filter_by_user = view_all and selected_user_id is not None
        data = get_dashboard_data(selected_user, view_all=view_all, filter_by_user=filter_by_user)
        
        # Serialize campaigns
        from django.utils import timezone
        now = timezone.now()
        campaigns_data = []
        for campaign in data['recent_campaigns']:
            # Calculate duration if campaign is completed
            duration_str = None
            elapsed_str = None
            if campaign.completed_at:
                # Use sent_at as start time if available, otherwise use created_at
                start_time = campaign.sent_at if campaign.sent_at else campaign.created_at
                duration = campaign.completed_at - start_time
                total_seconds = int(duration.total_seconds())
                
                # Format duration
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                seconds = total_seconds % 60
                
                if hours > 0:
                    duration_str = f"{hours}h {minutes}m {seconds}s"
                elif minutes > 0:
                    duration_str = f"{minutes}m {seconds}s"
                else:
                    duration_str = f"{seconds}s"
            elif campaign.status == 'sending':
                # Campaign is currently sending - calculate elapsed time
                start_time = campaign.sent_at if campaign.sent_at else campaign.created_at
                elapsed = now - start_time
                total_seconds = int(elapsed.total_seconds())
                # Ensure non-negative
                if total_seconds < 0:
                    total_seconds = 0
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                seconds = total_seconds % 60
                if hours > 0:
                    elapsed_str = f"{hours}h {minutes}m {seconds}s"
                elif minutes > 0:
                    elapsed_str = f"{minutes}m {seconds}s"
                else:
                    elapsed_str = f"{seconds}s"
            
            campaigns_data.append({
                'id': campaign.id,
                'name': campaign.name,
                'subject': campaign.subject,
                'status': campaign.status,
                'created_at': campaign.created_at.strftime('%b %d, %Y'),
                'created_at_iso': campaign.created_at.isoformat(),
                'sent_at': campaign.sent_at.strftime('%b %d, %Y %H:%M:%S') if campaign.sent_at else None,
                'sent_at_iso': campaign.sent_at.isoformat() if campaign.sent_at else campaign.created_at.isoformat(),
                'completed_at': campaign.completed_at.strftime('%b %d, %Y %H:%M:%S') if campaign.completed_at else None,
                'completed_at_iso': campaign.completed_at.isoformat() if campaign.completed_at else None,
                'duration': duration_str,
                'elapsed': elapsed_str,
                'start_time_iso': (campaign.sent_at if campaign.sent_at else campaign.created_at).isoformat(),
            })
        
        # Serialize emails
        emails_data = []
        for item in data['recent_emails_data']:
            email = item['email']
            contact = item['contact']
            
            # Get first name from contact or try CSV data
            first_name = getattr(contact, 'first_name', '') if contact else ''
            if not first_name and email.campaign and email.campaign.csv_data:
                try:
                    csv_recipients = json.loads(email.campaign.csv_data)
                    for recipient in csv_recipients:
                        recipient_email = None
                        for key in ['email', 'Email', 'EMAIL', 'e-mail', 'E-mail', 'E-Mail']:
                            if key in recipient and recipient[key]:
                                recipient_email = recipient[key].strip().lower()
                                break
                        
                        if recipient_email and email.recipient_email and recipient_email == email.recipient_email.lower():
                            first_name = (recipient.get('First Name') or 
                                         recipient.get('first_name') or 
                                         recipient.get('FirstName') or
                                         recipient.get('first name') or
                                         recipient.get('FIRST NAME') or
                                         recipient.get('name') or
                                         recipient.get('Name') or '')
                            break
                except Exception as e:
                    print(f"Error parsing CSV data for campaign {email.campaign.id if email.campaign else 'N/A'}: {str(e)}")
            
            emails_data.append({
                'id': email.id,
                'recipient_email': email.recipient_email,
                'subject': email.subject,
                'status': email.status,
                'sent_at': email.sent_at.strftime('%b %d, %H:%M'),
                'sent_at_iso': email.sent_at.isoformat(),
                'campaign_id': email.campaign.id if email.campaign else None,
                'campaign_name': email.campaign.name if email.campaign else 'N/A',
                'first_name': first_name,
                'last_name': getattr(contact, 'last_name', '') if contact else '',
                'company_name': getattr(contact, 'company_name', '') if contact else '',
                'title': getattr(contact, 'title', '') if contact else '',
            })
        
        # Serialize last login/logout
        last_login_data = None
        if data['last_login']:
            last_login_data = {
                'timestamp': data['last_login'].timestamp.strftime('%b %d, %Y %H:%M')
            }
        
        last_logout_data = None
        if data['last_logout']:
            last_logout_data = {
                'timestamp': data['last_logout'].timestamp.strftime('%b %d, %Y %H:%M')
            }
        
        return JsonResponse({
            'success': True,
            'data': {
                'total_emails': data['total_emails'],
                'total_campaigns': data['total_campaigns'],
                'campaigns_sent': data['campaigns_sent'],
                'active_campaigns': data['active_campaigns'],
                'total_contacts': data['total_contacts'],
                'sent_emails': data['sent_emails'],
                'failed_emails': data['failed_emails'],
                'bounce_emails': data.get('bounce_emails', 0),
                'recent_campaigns': campaigns_data,
                'recent_emails': emails_data,
                'last_login': last_login_data,
                'last_logout': last_logout_data,
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
def campaign_progress_api(request, campaign_id):
    """API endpoint to get campaign progress (sent/total emails)"""
    try:
        campaign = Campaign.objects.get(id=campaign_id, created_by=request.user)
        
        # Get total emails for this campaign (from CSV data or EmailLog)
        total_emails = 0
        if campaign.csv_data:
            try:
                recipients = json.loads(campaign.csv_data)
                total_emails = len(recipients)
            except:
                pass
        
        # If no CSV data, count from EmailLog
        if total_emails == 0:
            total_emails = EmailLog.objects.filter(campaign=campaign).count()
        
        # Get sent emails count
        sent_count = EmailLog.objects.filter(campaign=campaign, status='sent').count()
        
        # Get failed emails count
        failed_count = EmailLog.objects.filter(campaign=campaign, status='failed').count()
        
        # Calculate progress percentage
        progress_percent = (sent_count / total_emails * 100) if total_emails > 0 else 0
        
        return JsonResponse({
            'success': True,
            'data': {
                'campaign_id': campaign.id,
                'total_emails': total_emails,
                'sent_count': sent_count,
                'failed_count': failed_count,
                'progress_percent': round(progress_percent, 1),
                'status': campaign.status
            }
        })
    except Campaign.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Campaign not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["GET"])
def get_bounces_api(request):
    """API endpoint to get existing bounce emails (for display on page load)"""
    try:
        view_all = can_view_all_data(request.user)
        # Check if a specific user is selected
        selected_user_id = request.GET.get('user_id', None)
        selected_user = None
        
        print(f"get_bounces_api: view_all={view_all}, selected_user_id={selected_user_id}, request.user={request.user.id}")
        
        if view_all and selected_user_id:
            # Admin viewing specific user
            try:
                selected_user = User.objects.get(id=selected_user_id)
                print(f"get_bounces_api: Admin viewing selected_user={selected_user.id}")
            except User.DoesNotExist:
                selected_user = request.user
                print(f"get_bounces_api: Selected user not found, using request.user")
        else:
            # Admin viewing all data OR non-admin viewing own data
            selected_user = request.user
            if view_all:
                print(f"get_bounces_api: Admin viewing ALL data (no user filter)")
            else:
                print(f"get_bounces_api: Non-admin viewing own data")
        
        # Get ALL bounce emails from database for display
        if view_all and selected_user_id:
            # Admin viewing specific user: get that user's bounces
            bounce_emails = EmailLog.objects.filter(campaign__created_by=selected_user, status='bounce').order_by('-sent_at')
            print(f"get_bounces_api: Filtering by selected_user={selected_user.id}, count={bounce_emails.count()}")
        elif view_all:
            # Admin viewing all data: get ALL bounces
            bounce_emails = EmailLog.objects.filter(status='bounce').order_by('-sent_at')
            print(f"get_bounces_api: Getting ALL bounces (admin), count={bounce_emails.count()}")
        else:
            # Non-admin: get only their own bounces
            bounce_emails = EmailLog.objects.filter(campaign__created_by=request.user, status='bounce').order_by('-sent_at')
            print(f"get_bounces_api: Filtering by request.user={request.user.id}, count={bounce_emails.count()}")
        bounce_emails_data = []
        for email_log in bounce_emails:
            bounce_emails_data.append({
                'id': email_log.id,
                'recipient_email': email_log.recipient_email,
                'subject': email_log.subject,
                'status': email_log.status,
                'sent_at': email_log.sent_at.strftime('%b %d, %H:%M') if email_log.sent_at else '',
                'sent_at_iso': email_log.sent_at.isoformat() if email_log.sent_at else '',
                'error_message': email_log.error_message or '',
                'campaign_id': email_log.campaign.id if email_log.campaign else None,
                'campaign_name': email_log.campaign.name if email_log.campaign else 'N/A',
                'is_unmatched': False
            })
        
        # Also get unmatched bounces from BounceRecord (those not in EmailLog)
        try:
            from datetime import timedelta
            recent_cutoff = timezone.now() - timedelta(days=30)  # Show bounces from last 30 days
            if view_all and selected_user_id:
                # Get selected user's email addresses to match bounces
                user_email_logs = EmailLog.objects.filter(campaign__created_by=selected_user).values_list('recipient_email', flat=True).distinct()
                unmatched_records = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    recipient_email__in=user_email_logs,
                    detected_at__gte=recent_cutoff
                ).order_by('-detected_at')
            elif view_all:
                unmatched_records = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    detected_at__gte=recent_cutoff
                ).order_by('-detected_at')
            else:
                # Get user's email addresses to match bounces
                user_email_logs = EmailLog.objects.filter(campaign__created_by=request.user).values_list('recipient_email', flat=True).distinct()
                unmatched_records = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    recipient_email__in=user_email_logs,
                    detected_at__gte=recent_cutoff
                ).order_by('-detected_at')
            
            for record in unmatched_records:
                bounce_emails_data.append({
                    'id': None,
                    'recipient_email': record.recipient_email,
                    'subject': record.subject or 'Bounce notification',
                    'status': 'bounce',
                    'sent_at': record.detected_at.strftime('%b %d, %H:%M') if record.detected_at else '',
                    'sent_at_iso': record.detected_at.isoformat() if record.detected_at else '',
                    'error_message': record.bounce_reason or '',
                    'campaign_id': None,
                    'campaign_name': 'N/A',
                    'is_unmatched': True
                })
        except Exception:
            pass  # BounceRecord might not exist yet
        
        return JsonResponse({
            'success': True,
            'data': {
                'bounce_emails': bounce_emails_data,
                'total': len(bounce_emails_data)
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def check_bounces_api(request):
    """API endpoint to check for NEW email bounces (only checks for new ones, not already detected)"""
    try:
        from email_app.bounce_detector import BounceDetector
        from datetime import timedelta
        
        mailbox = request.POST.get('mailbox', 'INBOX')
        limit = int(request.POST.get('limit', 200))
        selected_user_id = request.POST.get('user_id', None)
        
        view_all = can_view_all_data(request.user)
        # Check if a specific user is selected
        selected_user = None
        if view_all and selected_user_id:
            try:
                selected_user = User.objects.get(id=selected_user_id)
            except User.DoesNotExist:
                selected_user = request.user
        else:
            selected_user = request.user
        
        # Get already detected bounce emails (from BounceRecord) to filter them out
        already_detected_emails = set()
        try:
            recent_cutoff = timezone.now() - timedelta(days=30)
            if view_all and selected_user_id:
                # Admin viewing specific user: get that user's email addresses
                user_email_logs = EmailLog.objects.filter(campaign__created_by=selected_user).values_list('recipient_email', flat=True).distinct()
                detected_records = BounceRecord.objects.filter(
                    recipient_email__in=user_email_logs,
                    detected_at__gte=recent_cutoff
                ).values_list('recipient_email', flat=True)
            elif view_all:
                # Admin viewing all data: get ALL detected bounces (no user filter)
                detected_records = BounceRecord.objects.filter(
                    detected_at__gte=recent_cutoff
                ).values_list('recipient_email', flat=True)
            else:
                # Non-admin: get only their own email addresses
                user_email_logs = EmailLog.objects.filter(campaign__created_by=request.user).values_list('recipient_email', flat=True).distinct()
                detected_records = BounceRecord.objects.filter(
                    recipient_email__in=user_email_logs,
                    detected_at__gte=recent_cutoff
                ).values_list('recipient_email', flat=True)
            already_detected_emails = {email.lower() for email in detected_records}
        except Exception:
            pass  # BounceRecord might not exist yet
        
        detector = BounceDetector()
        bounces = detector.check_bounces(mailbox=mailbox, limit=limit)
        
        # Filter out already detected bounces - only process NEW ones
        new_bounces = []
        for bounce in bounces:
            if bounce.get('recipient_email') and bounce['recipient_email'].lower() not in already_detected_emails:
                new_bounces.append(bounce)
        
        # Get existing bounce emails from database for display
        if view_all and selected_user_id:
            bounce_emails = EmailLog.objects.filter(campaign__created_by=selected_user, status='bounce').order_by('-sent_at')
        elif view_all:
            bounce_emails = EmailLog.objects.filter(status='bounce').order_by('-sent_at')
        else:
            bounce_emails = EmailLog.objects.filter(campaign__created_by=request.user, status='bounce').order_by('-sent_at')
        bounce_emails_data = []
        for email_log in bounce_emails:
            bounce_emails_data.append({
                'id': email_log.id,
                'recipient_email': email_log.recipient_email,
                'subject': email_log.subject,
                'status': email_log.status,
                'sent_at': email_log.sent_at.strftime('%b %d, %H:%M') if email_log.sent_at else '',
                'sent_at_iso': email_log.sent_at.isoformat() if email_log.sent_at else '',
                'error_message': email_log.error_message or '',
                'campaign_id': email_log.campaign.id if email_log.campaign else None,
                'campaign_name': email_log.campaign.name if email_log.campaign else 'N/A',
                'is_unmatched': False
            })
        
        # Also get unmatched bounces from BounceRecord
        try:
            recent_cutoff = timezone.now() - timedelta(days=30)
            if view_all and selected_user_id:
                # Get selected user's email addresses
                user_email_logs = EmailLog.objects.filter(campaign__created_by=selected_user).values_list('recipient_email', flat=True).distinct()
                unmatched_records = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    recipient_email__in=user_email_logs,
                    detected_at__gte=recent_cutoff
                ).order_by('-detected_at')
            elif view_all:
                unmatched_records = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    detected_at__gte=recent_cutoff
                ).order_by('-detected_at')
            else:
                user_email_logs = EmailLog.objects.filter(campaign__created_by=request.user).values_list('recipient_email', flat=True).distinct()
                unmatched_records = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    recipient_email__in=user_email_logs,
                    detected_at__gte=recent_cutoff
                ).order_by('-detected_at')
            
            for record in unmatched_records:
                # Check if already in bounce_emails_data
                found = any(
                    email['recipient_email'].lower() == record.recipient_email.lower()
                    for email in bounce_emails_data
                )
                if not found:
                    bounce_emails_data.append({
                        'id': None,
                        'recipient_email': record.recipient_email,
                        'subject': record.subject or 'Bounce notification',
                        'status': 'bounce',
                        'sent_at': record.detected_at.strftime('%b %d, %H:%M') if record.detected_at else '',
                        'sent_at_iso': record.detected_at.isoformat() if record.detected_at else '',
                        'error_message': record.bounce_reason or '',
                        'campaign_id': None,
                        'campaign_name': 'N/A',
                        'is_unmatched': True
                    })
        except Exception:
            pass
        
        if new_bounces:
            # Only update status for NEW bounces
            # Pass selected_user to filter by user's campaigns (for non-admin or admin viewing specific user)
            # If admin viewing all data, pass None to update all matching EmailLog entries
            update_user = None
            if not view_all:
                # Non-admin: only update their own emails
                update_user = request.user
            elif view_all and selected_user_id:
                # Admin viewing specific user: only update that user's emails
                update_user = selected_user
            # If admin viewing all data (view_all=True and no selected_user_id), update_user stays None (updates all)
            
            result = detector.update_bounce_status(new_bounces, user=update_user)
            
            # Get updated bounce emails after processing new bounces
            if view_all:
                bounce_emails = EmailLog.objects.filter(status='bounce').order_by('-sent_at')
            else:
                bounce_emails = EmailLog.objects.filter(campaign__created_by=request.user, status='bounce').order_by('-sent_at')
            bounce_emails_data = []
            for email_log in bounce_emails:
                bounce_emails_data.append({
                    'id': email_log.id,
                    'recipient_email': email_log.recipient_email,
                    'subject': email_log.subject,
                    'status': email_log.status,
                    'sent_at': email_log.sent_at.strftime('%b %d, %H:%M') if email_log.sent_at else '',
                    'sent_at_iso': email_log.sent_at.isoformat() if email_log.sent_at else '',
                    'error_message': email_log.error_message or '',
                    'campaign_id': email_log.campaign.id if email_log.campaign else None,
                    'campaign_name': email_log.campaign.name if email_log.campaign else 'N/A',
                    'is_unmatched': False
                })
            
            # Get unmatched bounces from BounceRecord - filter by user
            try:
                recent_cutoff = timezone.now() - timedelta(days=30)
                user_email_logs = EmailLog.objects.filter(campaign__created_by=request.user).values_list('recipient_email', flat=True).distinct()
                unmatched_records = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    recipient_email__in=user_email_logs,
                    detected_at__gte=recent_cutoff
                ).order_by('-detected_at')
                
                for record in unmatched_records:
                    found = any(
                        email['recipient_email'].lower() == record.recipient_email.lower()
                        for email in bounce_emails_data
                    )
                    if not found:
                        bounce_emails_data.append({
                            'id': None,
                            'recipient_email': record.recipient_email,
                            'subject': record.subject or 'Bounce notification',
                            'status': 'bounce',
                            'sent_at': record.detected_at.strftime('%b %d, %H:%M') if record.detected_at else '',
                            'sent_at_iso': record.detected_at.isoformat() if record.detected_at else '',
                            'error_message': record.bounce_reason or '',
                            'campaign_id': None,
                            'campaign_name': 'N/A',
                            'is_unmatched': True
                        })
            except Exception:
                pass
            
            return JsonResponse({
                'success': True,
                'data': {
                    'total_bounces': len(new_bounces),  # Only count NEW bounces
                    'updated': result['updated'],
                    'not_found': result['not_found'],
                    'bounce_emails': bounce_emails_data,  # Return ALL bounce emails (existing + new)
                    'total_bounce_emails_in_db': len([e for e in bounce_emails_data if not e.get('is_unmatched')]),
                    'unmatched_bounces': len([e for e in bounce_emails_data if e.get('is_unmatched')])
                }
            })
        else:
            # No NEW bounces found, but return existing bounce emails from database
            return JsonResponse({
                'success': True,
                'data': {
                    'total_bounces': 0,
                    'updated': 0,
                    'not_found': 0,
                    'bounce_emails': bounce_emails_data,
                    'total_bounce_emails_in_db': len([e for e in bounce_emails_data if not e.get('is_unmatched')]),
                    'unmatched_bounces': len([e for e in bounce_emails_data if e.get('is_unmatched')])
                },
                'message': 'No new bounces detected in inbox'
            })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
def email_details_api(request, email_id):
    """API endpoint to get email details including body content"""
    try:
        # Filter by user's campaigns directly
        email_log = EmailLog.objects.select_related('campaign').filter(campaign__created_by=request.user).get(id=email_id)
        
        # Get email body from campaign if available
        email_body = ''
        is_html = False
        if email_log.campaign:
            email_body = email_log.campaign.body or ''
            is_html = email_log.campaign.is_html
        
        return JsonResponse({
            'success': True,
            'data': {
                'id': email_log.id,
                'recipient_email': email_log.recipient_email,
                'subject': email_log.subject,
                'body': email_body,
                'is_html': is_html,
                'status': email_log.status,
                'sent_at': email_log.sent_at.isoformat() if email_log.sent_at else '',
                'error_message': email_log.error_message or '',
                'campaign_id': email_log.campaign.id if email_log.campaign else None,
                'campaign_name': email_log.campaign.name if email_log.campaign else 'N/A',
            }
        })
    except EmailLog.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Email not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
def campaign_statistics_api(request, campaign_id=None):
    """API endpoint to get campaign statistics (sent, failed, bounce)"""
    try:
        view_all = can_view_all_data(request.user)
        # Handle both URL patterns: with campaign_id and without
        if campaign_id is not None:
            # Get statistics for a specific campaign
            try:
                if view_all:
                    campaign = Campaign.objects.get(id=campaign_id)
                else:
                    campaign = Campaign.objects.get(id=campaign_id, created_by=request.user)
            except Campaign.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Campaign not found'
                }, status=404)
            
            # Get email counts for this campaign
            sent_count = EmailLog.objects.filter(campaign=campaign, status='sent').count()
            failed_count = EmailLog.objects.filter(campaign=campaign, status='failed').count()
            # Bounce count: EmailLog bounces + unmatched BounceRecord entries
            try:
                from datetime import timedelta
                recent_cutoff = timezone.now() - timedelta(days=30)
                email_log_bounces = EmailLog.objects.filter(campaign=campaign, status='bounce').count()
                # Count unmatched bounces from BounceRecord (check if recipient email matches campaign emails)
                # Get all recipient emails from this campaign
                campaign_emails = set(EmailLog.objects.filter(campaign=campaign).values_list('recipient_email', flat=True))
                # Count unmatched bounces where recipient email is in campaign emails
                unmatched_bounces = BounceRecord.objects.filter(
                    email_log__isnull=True,
                    detected_at__gte=recent_cutoff,
                    recipient_email__in=campaign_emails
                ).count() if campaign_emails else 0
                bounce_count = email_log_bounces + unmatched_bounces
            except Exception:
                # Fallback to EmailLog if BounceRecord doesn't exist yet
                bounce_count = EmailLog.objects.filter(campaign=campaign, status='bounce').count()
            total_count = sent_count + failed_count + bounce_count
            
            return JsonResponse({
                'success': True,
                'data': {
                    'campaign_id': campaign.id,
                    'campaign_name': campaign.name,
                    'sent': sent_count,
                    'failed': failed_count,
                    'bounce': bounce_count,
                    'total': total_count,
                    'is_overall': False
                }
            })
        else:
            # Get overall statistics for all campaigns
            if view_all:
                sent_count = EmailLog.objects.filter(status='sent').count()
                failed_count = EmailLog.objects.filter(status='failed').count()
                try:
                    from datetime import timedelta
                    recent_cutoff = timezone.now() - timedelta(days=30)
                    email_log_bounces = EmailLog.objects.filter(status='bounce').count()
                    unmatched_bounces = BounceRecord.objects.filter(
                        email_log__isnull=True,
                        detected_at__gte=recent_cutoff
                    ).count()
                    bounce_count = email_log_bounces + unmatched_bounces
                except Exception:
                    bounce_count = EmailLog.objects.filter(status='bounce').count()
            else:
                sent_count = EmailLog.objects.filter(campaign__created_by=request.user, status='sent').count()
                failed_count = EmailLog.objects.filter(campaign__created_by=request.user, status='failed').count()
                try:
                    from datetime import timedelta
                    recent_cutoff = timezone.now() - timedelta(days=30)
                    email_log_bounces = EmailLog.objects.filter(campaign__created_by=request.user, status='bounce').count()
                    user_email_logs = EmailLog.objects.filter(campaign__created_by=request.user).values_list('recipient_email', flat=True).distinct()
                    unmatched_bounces = BounceRecord.objects.filter(
                        email_log__isnull=True,
                        recipient_email__in=user_email_logs,
                        detected_at__gte=recent_cutoff
                    ).count()
                    bounce_count = email_log_bounces + unmatched_bounces
                except Exception:
                    bounce_count = EmailLog.objects.filter(campaign__created_by=request.user, status='bounce').count()
            total_count = sent_count + failed_count + bounce_count
            
            return JsonResponse({
                'success': True,
                'data': {
                    'campaign_id': None,
                    'campaign_name': 'All Campaigns',
                    'sent': sent_count,
                    'failed': failed_count,
                    'bounce': bounce_count,
                    'total': total_count,
                    'is_overall': True
                }
            })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
def campaign_emails_api(request, campaign_id):
    """API endpoint to get all emails for a specific campaign"""
    try:
        view_all = can_view_all_data(request.user)
        print(f"campaign_emails_api called: campaign_id={campaign_id}, user={request.user} (ID: {request.user.id}), view_all={view_all}")
        
        # Get campaign
        try:
            if view_all:
                campaign = Campaign.objects.get(id=campaign_id)
            else:
                campaign = Campaign.objects.get(id=campaign_id, created_by=request.user)
        except Campaign.DoesNotExist:
            print(f"Campaign {campaign_id} does not exist")
            return JsonResponse({
                'success': False,
                'error': 'Campaign not found'
            }, status=404)
        
        # Get all emails for this campaign (works for both sending and completed campaigns)
        # Order by sent_at descending (nulls will be last)
        campaign_emails = EmailLog.objects.filter(campaign=campaign).order_by('-sent_at', '-id')
        
        # Get contacts for all emails (handle empty list case, case-insensitive lookup)
        email_addresses = [email.recipient_email for email in campaign_emails if email.recipient_email]
        contacts_dict = {}
        if email_addresses:
            # Get all contacts and create case-insensitive lookup
            if view_all:
                all_contacts = Contact.objects.filter(email__in=email_addresses)
            else:
                all_contacts = Contact.objects.filter(created_by=request.user, email__in=email_addresses)
            for contact in all_contacts:
                # Store with lowercase email as key
                contacts_dict[contact.email.lower()] = contact
            # Also create reverse lookup by original email
            for email_addr in email_addresses:
                if email_addr.lower() in contacts_dict:
                    contacts_dict[email_addr] = contacts_dict[email_addr.lower()]
        
        # Load CSV data from campaign to extract first names
        csv_recipients_dict = {}
        if campaign.csv_data:
            try:
                csv_recipients = json.loads(campaign.csv_data)
                # Create a lookup dict by email (case-insensitive)
                for recipient in csv_recipients:
                    # Try to find email in various possible keys
                    email_key = None
                    for key in ['email', 'Email', 'EMAIL', 'e-mail', 'E-mail', 'E-Mail']:
                        if key in recipient and recipient[key]:
                            email_key = recipient[key].strip().lower()
                            break
                    if email_key:
                        # Store with lowercase key for case-insensitive lookup
                        csv_recipients_dict[email_key] = recipient
            except Exception as e:
                print(f"Error parsing CSV data: {str(e)}")
        
        # Serialize emails with contact data (works for both sending and completed campaigns)
        emails_data = []
        for email in campaign_emails:
            # Try case-insensitive lookup for contact
            contact = None
            if email.recipient_email:
                contact = contacts_dict.get(email.recipient_email) or contacts_dict.get(email.recipient_email.lower())
            
            # Try to get first name from CSV data if contact doesn't have it
            first_name = ''
            last_name = ''
            company_name = ''
            title = ''
            
            if contact:
                first_name = contact.first_name or ''
                last_name = contact.last_name or ''
                company_name = contact.company_name or ''
                title = contact.title or ''
            
            # If no first name from contact, try CSV data
            if not first_name and email.recipient_email:
                csv_recipient = csv_recipients_dict.get(email.recipient_email.lower())
                if csv_recipient:
                    # Try various possible keys for first name
                    first_name = (csv_recipient.get('First Name') or 
                                 csv_recipient.get('first_name') or 
                                 csv_recipient.get('FirstName') or
                                 csv_recipient.get('first name') or
                                 csv_recipient.get('FIRST NAME') or '')
                    last_name = (csv_recipient.get('Last Name') or 
                                csv_recipient.get('last_name') or 
                                csv_recipient.get('LastName') or
                                csv_recipient.get('last name') or
                                csv_recipient.get('LAST NAME') or '')
                    company_name = (csv_recipient.get('Company Name') or 
                                   csv_recipient.get('company_name') or 
                                   csv_recipient.get('CompanyName') or
                                   csv_recipient.get('company name') or
                                   csv_recipient.get('COMPANY NAME') or '')
                    title = (csv_recipient.get('Title') or 
                            csv_recipient.get('title') or 
                            csv_recipient.get('TITLE') or '')
            
            emails_data.append({
                'id': email.id,
                'recipient_email': email.recipient_email or '',
                'subject': email.subject or '',
                'status': email.status or 'unknown',
                'sent_at': email.sent_at.strftime('%b %d, %H:%M') if email.sent_at else '',
                'sent_at_iso': email.sent_at.isoformat() if email.sent_at else '',
                'campaign_id': campaign.id,
                'campaign_name': campaign.name,
                'first_name': first_name,
                'last_name': last_name,
                'company_name': company_name,
                'title': title,
                'error_message': email.error_message or '',
            })
        
        print(f"Campaign {campaign_id} ({campaign.name}) - Status: {campaign.status}, Total emails: {len(emails_data)}")
        
        return JsonResponse({
            'success': True,
            'data': {
                'campaign_id': campaign.id,
                'campaign_name': campaign.name,
                'emails': emails_data,
                'total': len(emails_data)
            }
        })
    except Campaign.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Campaign not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
def emails_by_status_api(request):
    """API endpoint to get all emails by status
    
    Behavior:
    - Admin (view_all=True) with no user_id: Returns ALL emails (all users)
    - Admin (view_all=True) with user_id: Returns emails for selected user only
    - Non-admin (view_all=False): Returns only their own emails
    """
    try:
        view_all = can_view_all_data(request.user)
        status = request.GET.get('status', '')
        selected_user_id = request.GET.get('user_id', None)
        selected_user = None
        
        # Debug logging
        print(f"emails_by_status_api: status={status}, view_all={view_all}, selected_user_id={selected_user_id}, request.user={request.user.id}")
        
        if view_all and selected_user_id:
            # Admin viewing specific user's data
            try:
                selected_user = User.objects.get(id=selected_user_id)
                print(f"emails_by_status_api: Admin viewing selected_user={selected_user.id} ({selected_user.username})")
            except User.DoesNotExist:
                selected_user = request.user
                print(f"emails_by_status_api: Selected user not found, using request.user={request.user.id}")
        else:
            # Admin viewing all data OR non-admin viewing own data
            selected_user = request.user
            if view_all:
                print(f"emails_by_status_api: Admin viewing ALL data (no user filter)")
            else:
                print(f"emails_by_status_api: Non-admin viewing own data (user={request.user.id})")
        
        if not status:
            return JsonResponse({
                'success': False,
                'error': 'Status parameter is required'
            }, status=400)
        
        # Get all emails by status
        # For bounce status, we need to match the count logic exactly
        if status == 'bounce':
            # For bounce, use the same logic as the dashboard count
            if view_all and selected_user_id:
                # Show emails from selected user's campaigns
                emails = EmailLog.objects.filter(
                    status=status,
                    campaign__created_by=selected_user
                ).select_related('campaign', 'campaign__created_by').order_by('-sent_at')
                print(f"emails_by_status_api: Filtering bounce emails by selected_user={selected_user.id}, count={emails.count()}")
            elif view_all:
                # Admin: show all EmailLog bounces (no date restriction for EmailLog, but unmatched bounces will be filtered by 30 days)
                emails = EmailLog.objects.filter(status=status).select_related('campaign', 'campaign__created_by').order_by('-sent_at')
                print(f"emails_by_status_api: Showing all bounce emails (admin), count={emails.count()}")
            else:
                # Non-admin: show only their own emails (from their campaigns)
                emails = EmailLog.objects.filter(
                    status=status,
                    campaign__created_by=request.user
                ).select_related('campaign', 'campaign__created_by').order_by('-sent_at')
                print(f"emails_by_status_api: Filtering bounce emails by request.user={request.user.id}, count={emails.count()}")
        else:
            # For other statuses, use normal filtering
            if view_all and selected_user_id:
                # Show emails from selected user's campaigns
                emails = EmailLog.objects.filter(
                    status=status,
                    campaign__created_by=selected_user
                ).select_related('campaign', 'campaign__created_by').order_by('-sent_at')
            elif view_all:
                # Admin: show all emails with this status
                emails = EmailLog.objects.filter(status=status).select_related('campaign', 'campaign__created_by').order_by('-sent_at')
            else:
                # Non-admin: show only their own emails (from their campaigns)
                emails = EmailLog.objects.filter(
                    status=status,
                    campaign__created_by=request.user
                ).select_related('campaign', 'campaign__created_by').order_by('-sent_at')
        
        # Get contacts for all emails
        email_addresses = [email.recipient_email for email in emails if email.recipient_email]
        contacts_dict = {}
        if email_addresses:
            if view_all and selected_user_id:
                all_contacts = Contact.objects.filter(created_by=selected_user, email__in=email_addresses)
            elif view_all:
                all_contacts = Contact.objects.filter(email__in=email_addresses)
            else:
                all_contacts = Contact.objects.filter(created_by=request.user, email__in=email_addresses)
            for contact in all_contacts:
                contacts_dict[contact.email.lower()] = contact
            for email_addr in email_addresses:
                if email_addr.lower() in contacts_dict:
                    contacts_dict[email_addr] = contacts_dict[email_addr.lower()]
        
        # Serialize emails
        emails_data = []
        for email in emails:
            contact = None
            if email.recipient_email:
                contact = contacts_dict.get(email.recipient_email) or contacts_dict.get(email.recipient_email.lower())
            
            emails_data.append({
                'id': email.id,
                'recipient_email': email.recipient_email or '',
                'subject': email.subject or '',
                'status': email.status or 'unknown',
                'sent_at': email.sent_at.strftime('%b %d, %H:%M') if email.sent_at else '',
                'sent_at_iso': email.sent_at.isoformat() if email.sent_at else '',
                'campaign_id': email.campaign.id if email.campaign else None,
                'campaign_name': email.campaign.name if email.campaign else 'N/A',
                'first_name': contact.first_name if contact else '',
                'error_message': email.error_message or '',
            })
        
        # For bounce status, also include unmatched BounceRecord entries (similar to get_bounces_api)
        # This must match the dashboard count logic exactly
        if status == 'bounce':
            try:
                from datetime import timedelta
                recent_cutoff = timezone.now() - timedelta(days=30)
                
                if view_all and selected_user_id:
                    # Admin viewing specific user: get that user's unmatched bounces
                    user_email_logs = EmailLog.objects.filter(campaign__created_by=selected_user).values_list('recipient_email', flat=True).distinct()
                    unmatched_records = BounceRecord.objects.filter(
                        email_log__isnull=True,
                        recipient_email__in=user_email_logs,
                        detected_at__gte=recent_cutoff
                    ).order_by('-detected_at')
                    print(f"emails_by_status_api: Getting unmatched bounces for selected_user={selected_user.id}, count={unmatched_records.count()}")
                elif view_all:
                    # Admin viewing all data: get ALL unmatched bounces (from all users)
                    unmatched_records = BounceRecord.objects.filter(
                        email_log__isnull=True,
                        detected_at__gte=recent_cutoff
                    ).order_by('-detected_at')
                    print(f"emails_by_status_api: Getting all unmatched bounces (admin), count={unmatched_records.count()}")
                else:
                    # Non-admin: get only their own unmatched bounces
                    user_email_logs = EmailLog.objects.filter(campaign__created_by=request.user).values_list('recipient_email', flat=True).distinct()
                    unmatched_records = BounceRecord.objects.filter(
                        email_log__isnull=True,
                        recipient_email__in=user_email_logs,
                        detected_at__gte=recent_cutoff
                    ).order_by('-detected_at')
                    print(f"emails_by_status_api: Getting unmatched bounces for request.user={request.user.id}, count={unmatched_records.count()}")
                
                # Add unmatched bounces to the list
                for record in unmatched_records:
                    # Check if already in emails_data (to avoid duplicates)
                    found = any(
                        email['recipient_email'].lower() == record.recipient_email.lower()
                        for email in emails_data
                    )
                    if not found:
                        emails_data.append({
                            'id': None,
                            'recipient_email': record.recipient_email,
                            'subject': record.subject or 'Bounce notification',
                            'status': 'bounce',
                            'sent_at': record.detected_at.strftime('%b %d, %H:%M') if record.detected_at else '',
                            'sent_at_iso': record.detected_at.isoformat() if record.detected_at else '',
                            'campaign_id': None,
                            'campaign_name': 'N/A',
                            'first_name': '',
                            'error_message': record.bounce_reason or '',
                        })
            except Exception:
                pass  # BounceRecord might not exist yet
        
        return JsonResponse({
            'success': True,
            'data': {
                'emails': emails_data,
                'total': len(emails_data),
                'status': status
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
def send_email_page(request):
    """Send email page"""
    # Check if user already has SMTP credentials in session (SpaceMail)
    has_credentials = request.session.get('smtp_username') and request.session.get('smtp_password')
    smtp_username = request.session.get('smtp_username', '')
    
    # Check if user has Gmail credentials in session
    has_gmail_credentials = request.session.get('gmail_username') and request.session.get('gmail_password')
    gmail_username = request.session.get('gmail_username', '')
    gmail_port = request.session.get('gmail_port', 587)
    
    return render(request, 'email_app/send_email_tailadmin.html', {
        'has_credentials': has_credentials,
        'smtp_username': smtp_username,
        'has_gmail_credentials': has_gmail_credentials,
        'gmail_username': gmail_username,
        'gmail_port': gmail_port
    })


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def spacemail_logout(request):
    """Logout from Spacemail (clear session credentials)"""
    try:
        # Clear SMTP credentials from session
        if 'smtp_username' in request.session:
            del request.session['smtp_username']
        if 'smtp_password' in request.session:
            del request.session['smtp_password']
        request.session.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Disconnected from Spacemail successfully'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def parse_csv_columns(request):
    """API endpoint to parse CSV columns"""
    try:
        if 'csv_file' not in request.FILES:
            return JsonResponse({
                'success': False,
                'error': 'No CSV file provided'
            }, status=400)
        
        csv_file = request.FILES['csv_file']
        
        # Save CSV temporarily
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.csv') as tmp_file:
            for chunk in csv_file.chunks():
                tmp_file.write(chunk)
            tmp_path = tmp_file.name
        
        try:
            # Read CSV to get column names and row count
            with open(tmp_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                columns = reader.fieldnames or []
                row_count = sum(1 for row in reader)  # Count remaining rows
            
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            
            return JsonResponse({
                'success': True,
                'columns': list(columns) if columns else [],
                'row_count': row_count
            })
        except Exception as e:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise e
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def test_smtp_connection(request):
    """API endpoint to test SMTP connection"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({
                'success': False,
                'error': 'Username and password are required'
            }, status=400)
        
        # Test connection with provided credentials
        sender = EmailSender(
            smtp_server='mail.spacemail.com',
            smtp_port=465,
            email=username,
            password=password
        )
        
        result = sender.test_connection()
        
        if result['success']:
            # Store credentials in session
            request.session['smtp_username'] = username
            request.session['smtp_password'] = password
            
            # Save as system provider
            from email_app.models import SystemProviderSettings
            SystemProviderSettings.objects.update_or_create(
                provider_type='spacemail',
                defaults={
                    'smtp_server': 'mail.spacemail.com',
                    'smtp_port': 465,
                    'smtp_username': username,
                    'smtp_password': password,
                    'is_active': True,
                    'updated_by': request.user
                }
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Connection successful!'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Connection failed')
            }, status=400)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def test_gmail_connection(request):
    """API endpoint to test Gmail SMTP connection"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        port = data.get('port', 587)
        
        if not username or not password:
            return JsonResponse({
                'success': False,
                'error': 'Username and password are required'
            }, status=400)
        
        if port not in [587, 465, 25]:
            return JsonResponse({
                'success': False,
                'error': 'Invalid port. Must be 587, 465, or 25'
            }, status=400)
        
        # Test connection with provided credentials
        sender = EmailSender(
            smtp_server='smtp.gmail.com',
            smtp_port=port,
            email=username,
            password=password
        )
        
        result = sender.test_connection()
        
        if result['success']:
            # Store Gmail credentials in session
            request.session['gmail_username'] = username
            request.session['gmail_password'] = password
            request.session['gmail_port'] = port
            
            # Save as system provider
            from email_app.models import SystemProviderSettings
            SystemProviderSettings.objects.update_or_create(
                provider_type='gmail',
                defaults={
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': port,
                    'smtp_username': username,
                    'smtp_password': password,
                    'is_active': True,
                    'updated_by': request.user
                }
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Connection successful!'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Connection failed')
            }, status=400)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def gmail_logout(request):
    """Logout from Gmail (clear session credentials)"""
    try:
        # Clear Gmail credentials from session
        if 'gmail_username' in request.session:
            del request.session['gmail_username']
        if 'gmail_password' in request.session:
            del request.session['gmail_password']
        if 'gmail_port' in request.session:
            del request.session['gmail_port']
        request.session.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Disconnected from Gmail successfully'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def send_email_api(request):
    """API endpoint to send emails"""
    try:
        # Prefer Gmail if configured, otherwise use SpaceMail, then defaults
        gmail_username = request.session.get('gmail_username')
        gmail_password = request.session.get('gmail_password')
        gmail_port = request.session.get('gmail_port', 587)
        
        if gmail_username and gmail_password:
            # Use Gmail configuration
            smtp_username = gmail_username
            smtp_password = gmail_password
            smtp_server = 'smtp.gmail.com'
            smtp_port = gmail_port
        else:
            # Use SpaceMail or defaults
            smtp_username = request.session.get('smtp_username') or settings.SENDER_EMAIL
            smtp_password = request.session.get('smtp_password') or settings.SENDER_PASSWORD
            smtp_server = 'mail.spacemail.com'
            smtp_port = 465
        
        sender = EmailSender(
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            email=smtp_username,
            password=smtp_password
        )
        
        # Create campaign if it's a bulk email OR if campaign name is provided
        campaign = None
        campaign_name = request.POST.get('campaign_name', '').strip()
        use_csv = request.POST.get('use_csv') == 'true'
        
        if use_csv or campaign_name:
            if not campaign_name:
                campaign_name = f"Campaign - {timezone.now().strftime('%Y-%m-%d %H:%M')}"
            
            campaign = Campaign.objects.create(
                name=campaign_name,
                subject=request.POST.get('subject', ''),
                body=request.POST.get('body', ''),
                is_html=request.POST.get('is_html') == 'true',
                created_by=request.user,
                status='sending' if use_csv else 'draft',
                sent_at=timezone.now() if use_csv else None  # Set sent_at when campaign starts sending
            )
        
        # Check if this is a JSON request (Content-Type: application/json)
        content_type = request.META.get('CONTENT_TYPE', '')
        if 'application/json' in content_type:
            # Handle JSON request
            try:
                data = json.loads(request.body)
                
                to_email = data.get('to_email')
                subject = data.get('subject')
                body = data.get('body')
                cc = data.get('cc', [])
                is_html = data.get('is_html', False)
                
                if not all([to_email, subject, body]):
                    return JsonResponse({
                        'success': False,
                        'error': 'Missing required fields: to_email, subject, body'
                    }, status=400)
                
                if is_html:
                    success = sender.send_html_email(
                        to_email=to_email,
                        subject=subject,
                        html_body=body,
                        cc=cc if isinstance(cc, list) else [cc] if cc else None
                    )
                else:
                    success = sender.send_simple_email(
                        to_email=to_email,
                        subject=subject,
                        body=body,
                        cc=cc if isinstance(cc, list) else [cc] if cc else None
                    )
                
                if success:
                    return JsonResponse({
                        'success': True,
                        'message': f'Email sent successfully to {to_email}'
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': 'Failed to send email'
                    }, status=500)
            except json.JSONDecodeError:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid JSON in request body'
                }, status=400)
        
        # Check if this is a file upload (multipart/form-data)
        elif request.FILES:
            # Handle file uploads
            csv_file = request.FILES.get('csv_file')
            attachment_file = request.FILES.get('attachment')
            
            # Get form data
            to_email = request.POST.get('to_email')
            subject = request.POST.get('subject')
            body = request.POST.get('body')
            cc = request.POST.get('cc', '')
            is_html = request.POST.get('is_html') == 'true'
            attributes = request.POST.get('attributes', '')
            use_csv = request.POST.get('use_csv') == 'true'
            
            # Parse attributes (comma-separated key:value pairs)
            attr_dict = {}
            if attributes:
                for attr in attributes.split(','):
                    if ':' in attr:
                        key, value = attr.split(':', 1)
                        attr_dict[key.strip()] = value.strip()
            
            # Handle CSV bulk email
            if use_csv and csv_file:
                # Save CSV temporarily
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.csv') as tmp_file:
                    for chunk in csv_file.chunks():
                        tmp_file.write(chunk)
                    tmp_path = tmp_file.name
                
                try:
                    # Load recipients from CSV
                    recipients = load_recipients_from_csv(tmp_path)
                    
                    if not recipients:
                        return JsonResponse({
                            'success': False,
                            'error': 'No recipients found in CSV file'
                        }, status=400)
                    
                    # Store CSV data in campaign for future restarts
                    if campaign:
                        campaign.csv_data = json.dumps(recipients)
                        campaign.attributes = attributes if attributes else ''
                        campaign.save()
                    
                    # Prepare subject and body templates (don't replace attributes yet - let CSV data handle it)
                    subject_template = subject
                    body_template = body
                    
                    # Note: Manual attributes will be merged with CSV data per-recipient during email sending
                    
                    # Handle attachment if provided
                    attachment_path = None
                    if attachment_file:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(attachment_file.name)[1]) as tmp_attach:
                            for chunk in attachment_file.chunks():
                                tmp_attach.write(chunk)
                            attachment_path = tmp_attach.name
                    
                    # Send bulk emails in batches of 100 with 30 second delay between batches
                    if attachment_path:
                        # Send bulk with attachment (custom implementation needed)
                        results = {'sent': [], 'failed': []}
                        total = len(recipients)
                        batch_size = 100
                        batch_delay = 30  # 30 seconds between batches
                        
                        # Process recipients in batches
                        for batch_start in range(0, total, batch_size):
                            # Check if campaign was paused before processing each batch
                            if campaign:
                                campaign.refresh_from_db()
                                if campaign.status != 'sending':
                                    print(f"\n⏸️  Campaign paused. Stopping email sending.")
                                    break
                            
                            batch_end = min(batch_start + batch_size, total)
                            batch_recipients = recipients[batch_start:batch_end]
                            batch_number = (batch_start // batch_size) + 1
                            total_batches = (total + batch_size - 1) // batch_size
                            
                            print(f"\n📦 Processing batch {batch_number}/{total_batches} (emails {batch_start + 1}-{batch_end} of {total})")
                            
                            for i, recipient in enumerate(batch_recipients, 1):
                                # Check if campaign was paused before sending each email
                                if campaign:
                                    campaign.refresh_from_db()
                                    if campaign.status != 'sending':
                                        print(f"\n⏸️  Campaign paused. Stopping email sending.")
                                        break
                                
                                global_index = batch_start + i
                            try:
                                # Normalize recipient keys
                                normalized_recipient = {k.lower(): v for k, v in recipient.items()}
                                normalized_recipient.update(recipient)
                                
                                # Merge with manual attributes (CSV data takes precedence)
                                if attr_dict:
                                    merged_data = {**attr_dict, **normalized_recipient}
                                    merged_data.update({k.lower(): v for k, v in merged_data.items()})
                                else:
                                    merged_data = normalized_recipient
                                
                                # Format subject and body safely with merged data
                                formatted_subject = sender._safe_format_template(subject_template, merged_data)
                                formatted_body = sender._safe_format_template(body_template, merged_data)
                                
                                # Get email with case-insensitive matching
                                recipient_email = sender._get_email_from_recipient(recipient)
                                
                                if recipient_email:
                                    print(f"[{global_index}/{total}] Sending to {recipient_email}...", end=" ")
                                    success = sender.send_email_with_attachment(
                                        to_email=recipient_email,
                                        subject=formatted_subject,
                                        body=formatted_body,
                                        attachment_path=attachment_path,
                                        is_html=is_html
                                    )
                                    
                                    # Get or create email log entry (with explicit sent_at timestamp)
                                    if campaign:
                                        email_log, created = EmailLog.objects.get_or_create(
                                            campaign=campaign,
                                            recipient_email=recipient_email,
                                            defaults={
                                                'subject': formatted_subject,
                                                'status': 'sent' if success else 'failed',
                                                'error_message': '' if success else 'Failed to send',
                                                'sent_at': timezone.now()  # Explicit timestamp
                                            }
                                        )
                                        
                                        if not created:
                                            # Update existing log
                                            email_log.status = 'sent' if success else 'failed'
                                            email_log.error_message = '' if success else 'Failed to send'
                                            email_log.sent_at = timezone.now()  # Update timestamp
                                            email_log.save()
                                    
                                    if success:
                                        results['sent'].append(recipient_email)
                                        print(f"✓ Sent successfully")
                                    else:
                                        results['failed'].append(recipient_email)
                                        print(f"✗ Failed to send")
                                else:
                                    results['failed'].append('unknown')
                            except Exception as e:
                                print(f"✗ Error: {str(e)}")
                                email = sender._get_email_from_recipient(recipient) or 'unknown'
                                # Create or update failed log entry (following restart process)
                                if campaign and email != 'unknown':
                                    EmailLog.objects.update_or_create(
                                        campaign=campaign,
                                        recipient_email=email,
                                        defaults={
                                            'subject': subject_template,
                                            'status': 'failed',
                                            'error_message': str(e),
                                            'sent_at': timezone.now()  # Explicit timestamp
                                        }
                                    )
                                results['failed'].append(email)
                                
                                # No delay between emails - send as fast as possible within batch
                            
                            # Check if campaign was paused before waiting for next batch
                            if campaign:
                                campaign.refresh_from_db()
                                if campaign.status != 'sending':
                                    print(f"\n⏸️  Campaign paused. Stopping email sending.")
                                    break
                            
                            # Wait before next batch (except after last batch)
                            if batch_end < total:
                                print(f"\n⏸️  Batch {batch_number} completed. Waiting {batch_delay} seconds before next batch...")
                                # Check status during delay (check every 5 seconds)
                                for _ in range(batch_delay // 5):
                                    time.sleep(5)
                                    if campaign:
                                        campaign.refresh_from_db()
                                        if campaign.status != 'sending':
                                            print(f"\n⏸️  Campaign paused during delay. Stopping email sending.")
                                            break
                                else:
                                    # If we didn't break, sleep the remaining time
                                    remaining_time = batch_delay % 5
                                    if remaining_time > 0:
                                        time.sleep(remaining_time)
                                        if campaign:
                                            campaign.refresh_from_db()
                                            if campaign.status != 'sending':
                                                print(f"\n⏸️  Campaign paused during delay. Stopping email sending.")
                                                break
                        
                        # Clean up attachment
                        if os.path.exists(attachment_path):
                            os.unlink(attachment_path)
                    else:
                        # Send bulk without attachment - following same process as restart
                        results = {'sent': [], 'failed': []}
                        total = len(recipients)
                        batch_size = 100
                        batch_delay = 30  # 30 seconds between batches
                        
                        # Process recipients in batches
                        for batch_start in range(0, total, batch_size):
                            # Check if campaign was paused before processing each batch
                            if campaign:
                                campaign.refresh_from_db()
                                if campaign.status != 'sending':
                                    print(f"\n⏸️  Campaign paused. Stopping email sending.")
                                    break
                            
                            batch_end = min(batch_start + batch_size, total)
                            batch_recipients = recipients[batch_start:batch_end]
                            batch_number = (batch_start // batch_size) + 1
                            total_batches = (total + batch_size - 1) // batch_size
                            
                            print(f"\n📦 Processing batch {batch_number}/{total_batches} (emails {batch_start + 1}-{batch_end} of {total})")
                            
                            for recipient in batch_recipients:
                                # Check if campaign was paused before sending each email
                                if campaign:
                                    campaign.refresh_from_db()
                                    if campaign.status != 'sending':
                                        print(f"\n⏸️  Campaign paused. Stopping email sending.")
                                        break
                                
                                email_address = sender._get_email_from_recipient(recipient)
                                if not email_address:
                                    continue
                                    
                                print(f"Processing email to {email_address}...")
                                try:
                                    # Normalize recipient keys
                                    normalized_recipient = {k.lower(): v for k, v in recipient.items()}
                                    normalized_recipient.update(recipient)
                                    
                                    # Merge with manual attributes (CSV data takes precedence)
                                    if attr_dict:
                                        merged_data = {**attr_dict, **normalized_recipient}
                                        merged_data.update({k.lower(): v for k, v in merged_data.items()})
                                    else:
                                        merged_data = normalized_recipient
                                    
                                    # Format subject and body with recipient data
                                    formatted_subject = sender._safe_format_template(subject_template, merged_data)
                                    formatted_body = sender._safe_format_template(body_template, merged_data)
                                    
                                    # Send email
                                    if is_html:
                                        success = sender.send_html_email(
                                            to_email=email_address,
                                            subject=formatted_subject,
                                            html_body=formatted_body
                                        )
                                    else:
                                        success = sender.send_simple_email(
                                            to_email=email_address,
                                            subject=formatted_subject,
                                            body=formatted_body
                                        )
                                    
                                    # Get or create email log entry (with explicit sent_at timestamp)
                                    if campaign:
                                        email_log, created = EmailLog.objects.get_or_create(
                                            campaign=campaign,
                                            recipient_email=email_address,
                                            defaults={
                                                'subject': formatted_subject,
                                                'status': 'sent' if success else 'failed',
                                                'error_message': '' if success else 'Failed to send',
                                                'sent_at': timezone.now()  # Explicit timestamp
                                            }
                                        )
                                        
                                        if not created:
                                            # Update existing log
                                            email_log.status = 'sent' if success else 'failed'
                                            email_log.error_message = '' if success else 'Failed to send'
                                            email_log.sent_at = timezone.now()  # Update timestamp
                                            email_log.save()
                                    
                                    if success:
                                        results['sent'].append(email_address)
                                        print(f"  ✓ Sent successfully to {email_address}")
                                    else:
                                        results['failed'].append(email_address)
                                        print(f"  ✗ Failed to send to {email_address}")
                                    
                                    # No delay between emails - send as fast as possible within batch
                                    
                                except Exception as e:
                                    print(f"  ✗ Error sending to {email_address}: {str(e)}")
                                    # Create or update failed log entry
                                    if campaign:
                                        EmailLog.objects.update_or_create(
                                            campaign=campaign,
                                            recipient_email=email_address,
                                            defaults={
                                                'subject': subject_template,
                                                'status': 'failed',
                                                'error_message': str(e)
                                            }
                                        )
                                    results['failed'].append(email_address)
                            
                            # Check if campaign was paused before waiting for next batch
                            if campaign:
                                campaign.refresh_from_db()
                                if campaign.status != 'sending':
                                    print(f"\n⏸️  Campaign paused. Stopping email sending.")
                                    break
                            
                            # Clear batch data from memory after processing
                            del batch_recipients
                            
                            # Wait before next batch (except after last batch)
                            if batch_end < total:
                                print(f"\n⏸️  Batch {batch_number} completed. Waiting {batch_delay} seconds before next batch...")
                                # Check status during delay (check every 5 seconds)
                                for _ in range(batch_delay // 5):
                                    time.sleep(5)
                                    if campaign:
                                        campaign.refresh_from_db()
                                        if campaign.status != 'sending':
                                            print(f"\n⏸️  Campaign paused during delay. Stopping email sending.")
                                            break
                                else:
                                    # If we didn't break, sleep the remaining time
                                    remaining_time = batch_delay % 5
                                    if remaining_time > 0:
                                        time.sleep(remaining_time)
                                        if campaign:
                                            campaign.refresh_from_db()
                                            if campaign.status != 'sending':
                                                print(f"\n⏸️  Campaign paused during delay. Stopping email sending.")
                                                break
                    
                    # Clean up CSV
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    
                    # Update campaign status (emails are already logged during sending loop)
                    if campaign:
                        campaign.refresh_from_db()
                        # Only mark as completed if still in 'sending' status (not paused)
                        if campaign.status == 'sending':
                            campaign.status = 'completed' if len(results['failed']) == 0 else 'completed'
                            campaign.sent_at = timezone.now()
                            campaign.completed_at = timezone.now()  # Set exact completion time
                            campaign.save()
                        else:
                            print(f"Campaign was paused, keeping status as '{campaign.status}'")
                        
                        # Note: Emails are already logged during the sending loop above (lines 893-907)
                        # No need to log again here to avoid duplicates
                        
                        # Save contacts from CSV
                        for recipient in recipients:
                            email_addr = sender._get_email_from_recipient(recipient)
                            if email_addr:
                                Contact.objects.update_or_create(
                                    email=email_addr,
                                    created_by=request.user,
                                    defaults={
                                        'first_name': recipient.get('First Name') or recipient.get('first_name', ''),
                                        'last_name': recipient.get('Last Name') or recipient.get('last_name', ''),
                                        'company_name': recipient.get('Company Name') or recipient.get('company_name', ''),
                                        'title': recipient.get('Title') or recipient.get('title', ''),
                                    }
                                )
                    
                    return JsonResponse({
                        'success': True,
                        'message': f'Bulk email campaign completed. Sent: {len(results["sent"])}, Failed: {len(results["failed"])}',
                        'results': results
                    })
                    
                except Exception as e:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    raise e
            
            # Single email with attachment
            elif attachment_file:
                # Save attachment temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(attachment_file.name)[1]) as tmp_file:
                    for chunk in attachment_file.chunks():
                        tmp_file.write(chunk)
                    attachment_path = tmp_file.name
                
                try:
                    # Merge attributes for formatting
                    recipient_data = {}
                    if attr_dict:
                        recipient_data.update(attr_dict)
                    
                    # Format body and subject with attributes using safe formatter
                    formatted_body = sender._safe_format_template(body, recipient_data)
                    formatted_subject = sender._safe_format_template(subject, recipient_data)
                    
                    success = sender.send_email_with_attachment(
                        to_email=to_email,
                        subject=formatted_subject,
                        body=formatted_body,
                        attachment_path=attachment_path,
                        is_html=is_html
                    )
                    
                    # Clean up
                    if os.path.exists(attachment_path):
                        os.unlink(attachment_path)
                    
                    if success:
                        # Log email
                        EmailLog.objects.create(
                            recipient_email=to_email,
                            subject=formatted_subject,
                            status='sent',
                            campaign=campaign if campaign else None
                        )
                        
                        # Save contact
                        Contact.objects.update_or_create(
                            email=to_email,
                            created_by=request.user,
                            defaults={
                                'first_name': attr_dict.get('First Name') or attr_dict.get('first_name', ''),
                                'company_name': attr_dict.get('Company Name') or attr_dict.get('company_name', ''),
                            }
                        )
                        
                        return JsonResponse({
                            'success': True,
                            'message': f'Email with attachment sent successfully to {to_email}'
                        })
                    else:
                        return JsonResponse({
                            'success': False,
                            'error': 'Failed to send email'
                        }, status=500)
                except Exception as e:
                    if os.path.exists(attachment_path):
                        os.unlink(attachment_path)
                    raise e
            
            # Single email without attachment
            else:
                # Merge attributes with recipient data for formatting
                recipient_data = {}
                if attr_dict:
                    recipient_data.update(attr_dict)
                
                # Format body with attributes using safe formatter
                formatted_body = sender._safe_format_template(body, recipient_data)
                formatted_subject = sender._safe_format_template(subject, recipient_data)
                
                cc_list = [e.strip() for e in cc.split(',')] if cc else None
                
                if is_html:
                    success = sender.send_html_email(
                        to_email=to_email,
                        subject=formatted_subject,
                        html_body=formatted_body,
                        cc=cc_list
                    )
                else:
                    success = sender.send_simple_email(
                        to_email=to_email,
                        subject=formatted_subject,
                        body=formatted_body,
                        cc=cc_list
                    )
                
                if success:
                    # Log email
                    EmailLog.objects.create(
                        recipient_email=to_email,
                        subject=formatted_subject,
                        status='sent',
                        campaign=campaign if campaign else None
                    )
                    
                    # Save contact
                    Contact.objects.update_or_create(
                        email=to_email,
                        defaults={
                            'first_name': attr_dict.get('First Name') or attr_dict.get('first_name', ''),
                            'company_name': attr_dict.get('Company Name') or attr_dict.get('company_name', ''),
                        }
                    )
                    
                    return JsonResponse({
                        'success': True,
                        'message': f'Email sent successfully to {to_email}'
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': 'Failed to send email'
                    }, status=500)
        
        # Handle form data request (multipart/form-data without files)
        else:
            # Merge attributes with recipient data for formatting
            recipient_data = {}
            attributes = request.POST.get('attributes', '')
            if attributes:
                attr_dict = {}
                for attr in attributes.split(','):
                    if ':' in attr:
                        key, value = attr.split(':', 1)
                        attr_dict[key.strip()] = value.strip()
                recipient_data.update(attr_dict)
            
            # Format body with attributes using safe formatter
            to_email = request.POST.get('to_email')
            subject = request.POST.get('subject')
            body = request.POST.get('body')
            cc = request.POST.get('cc', '')
            is_html = request.POST.get('is_html') == 'true'
            
            formatted_body = sender._safe_format_template(body, recipient_data)
            formatted_subject = sender._safe_format_template(subject, recipient_data)
            
            cc_list = [e.strip() for e in cc.split(',')] if cc else None
            
            if is_html:
                success = sender.send_html_email(
                    to_email=to_email,
                    subject=formatted_subject,
                    html_body=formatted_body,
                    cc=cc_list
                )
            else:
                success = sender.send_simple_email(
                    to_email=to_email,
                    subject=formatted_subject,
                    body=formatted_body,
                    cc=cc_list
                )
            
            if success:
                # Log email
                EmailLog.objects.create(
                    recipient_email=to_email,
                    subject=formatted_subject,
                    status='sent',
                    campaign=campaign if campaign else None
                )
                
                # Save contact
                if attributes:
                    attr_dict = {}
                    for attr in attributes.split(','):
                        if ':' in attr:
                            key, value = attr.split(':', 1)
                            attr_dict[key.strip()] = value.strip()
                    Contact.objects.update_or_create(
                        email=to_email,
                        defaults={
                            'first_name': attr_dict.get('First Name') or attr_dict.get('first_name', ''),
                            'company_name': attr_dict.get('Company Name') or attr_dict.get('company_name', ''),
                        }
                    )
                
                return JsonResponse({
                    'success': True,
                    'message': f'Email sent successfully to {to_email}'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Failed to send email'
                }, status=500)
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error in send_email_api: {str(e)}")
        print(f"Traceback: {error_trace}")
        return JsonResponse({
            'success': False,
            'error': f'Error sending email: {str(e)}'
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def restart_campaign(request, campaign_id):
    """API endpoint to restart a campaign and resend failed/unsent emails"""
    try:
        campaign = Campaign.objects.get(id=campaign_id, created_by=request.user)
        
        # Prefer Gmail if configured, otherwise use SpaceMail, then defaults
        gmail_username = request.session.get('gmail_username')
        gmail_password = request.session.get('gmail_password')
        gmail_port = request.session.get('gmail_port', 587)
        
        if gmail_username and gmail_password:
            # Use Gmail configuration
            smtp_username = gmail_username
            smtp_password = gmail_password
            smtp_server = 'smtp.gmail.com'
            smtp_port = gmail_port
        else:
            # Use SpaceMail or defaults
            smtp_username = request.session.get('smtp_username') or settings.SENDER_EMAIL
            smtp_password = request.session.get('smtp_password') or settings.SENDER_PASSWORD
            smtp_server = 'mail.spacemail.com'
            smtp_port = 465
        
        sender = EmailSender(
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            email=smtp_username,
            password=smtp_password
        )
        
        # Get stored CSV data from campaign (original data)
        recipients = []
        if campaign.csv_data:
            try:
                recipients = json.loads(campaign.csv_data)
                print(f"Loaded {len(recipients)} recipients from stored CSV data")
            except Exception as e:
                print(f"Error loading stored CSV data: {str(e)}")
        
        # If no stored CSV data, fall back to EmailLog entries
        if not recipients:
            all_email_logs = EmailLog.objects.filter(campaign=campaign)
            all_campaign_emails = set(all_email_logs.values_list('recipient_email', flat=True))
            sent_emails = set(all_email_logs.filter(status='sent').values_list('recipient_email', flat=True))
            failed_emails = set(all_email_logs.filter(status='failed').values_list('recipient_email', flat=True))
            emails_to_send = failed_emails | (all_campaign_emails - sent_emails)
            
            # Convert emails to recipient format
            for email_addr in emails_to_send:
                contact = Contact.objects.filter(created_by=request.user, email=email_addr).first()
                recipient = {'email': email_addr, 'Email': email_addr}
                if contact:
                    recipient.update({
                        'First Name': contact.first_name or '',
                        'first_name': contact.first_name or '',
                        'Last Name': contact.last_name or '',
                        'last_name': contact.last_name or '',
                        'Company Name': contact.company_name or '',
                        'company_name': contact.company_name or '',
                        'Title': contact.title or '',
                        'title': contact.title or '',
                    })
                recipients.append(recipient)
        
        # Get all email logs for this campaign
        all_email_logs = EmailLog.objects.filter(campaign=campaign)
        sent_emails = set(all_email_logs.filter(status='sent').values_list('recipient_email', flat=True))
        
        # Filter recipients: only send to failed or unsent emails
        recipients_to_send = []
        for recipient in recipients:
            email_addr = sender._get_email_from_recipient(recipient)
            if email_addr and email_addr not in sent_emails:
                recipients_to_send.append(recipient)
        
        total_emails_to_send = len(recipients_to_send)
        
        print(f"Restarting campaign {campaign_id}:")
        print(f"  - Total original recipients: {len(recipients)}")
        print(f"  - Already sent: {len(sent_emails)}")
        print(f"  - Will send to: {total_emails_to_send} emails")
        
        # Update campaign status
        campaign.status = 'sending'
        campaign.sent_at = timezone.now()  # Set sent_at when restarting
        campaign.save()
        
        results = {'sent': [], 'failed': []}
        
        # Get manual attributes if stored
        attr_dict = {}
        if campaign.attributes:
            for attr in campaign.attributes.split(','):
                if ':' in attr:
                    key, value = attr.split(':', 1)
                    attr_dict[key.strip()] = value.strip()
        
        # Process recipients in batches of 100 with 30 second delay between batches
        batch_size = 100
        batch_delay = 30  # 30 seconds between batches
        total = len(recipients_to_send)
        
        # Process recipients in batches
        for batch_start in range(0, total, batch_size):
            # Check if campaign was paused before processing each batch
            campaign.refresh_from_db()
            if campaign.status != 'sending':
                print(f"\n⏸️  Campaign paused. Stopping email sending.")
                break
            
            batch_end = min(batch_start + batch_size, total)
            batch_recipients = recipients_to_send[batch_start:batch_end]
            batch_number = (batch_start // batch_size) + 1
            total_batches = (total + batch_size - 1) // batch_size
            
            print(f"\n📦 Processing batch {batch_number}/{total_batches} (emails {batch_start + 1}-{batch_end} of {total})")
            
            for recipient in batch_recipients:
                # Check if campaign was paused before sending each email
                campaign.refresh_from_db()
                if campaign.status != 'sending':
                    print(f"\n⏸️  Campaign paused. Stopping email sending.")
                    break
                
                email_address = sender._get_email_from_recipient(recipient)
                if not email_address:
                    continue
                    
                print(f"Processing email to {email_address}...")
                try:
                    # Normalize recipient keys
                    normalized_recipient = {k.lower(): v for k, v in recipient.items()}
                    normalized_recipient.update(recipient)
                    
                    # Merge with manual attributes (CSV data takes precedence)
                    if attr_dict:
                        merged_data = {**attr_dict, **normalized_recipient}
                        merged_data.update({k.lower(): v for k, v in merged_data.items()})
                    else:
                        merged_data = normalized_recipient
                    
                    # Format subject and body with recipient data (using original campaign data)
                    formatted_subject = sender._safe_format_template(campaign.subject, merged_data)
                    formatted_body = sender._safe_format_template(campaign.body, merged_data)
                    
                    # Send email
                    if campaign.is_html:
                        success = sender.send_html_email(
                            to_email=email_address,
                            subject=formatted_subject,
                            html_body=formatted_body
                        )
                    else:
                        success = sender.send_simple_email(
                            to_email=email_address,
                            subject=formatted_subject,
                            body=formatted_body
                        )
                    
                    # Get or create email log entry (with explicit sent_at timestamp)
                    email_log, created = EmailLog.objects.get_or_create(
                        campaign=campaign,
                        recipient_email=email_address,
                        defaults={
                            'subject': formatted_subject,
                            'status': 'sent' if success else 'failed',
                            'error_message': '' if success else 'Failed to send',
                            'sent_at': timezone.now()  # Explicit timestamp
                        }
                    )
                    
                    if not created:
                        # Update existing log
                        email_log.status = 'sent' if success else 'failed'
                        email_log.error_message = '' if success else 'Failed to send'
                        email_log.sent_at = timezone.now()  # Update timestamp
                        email_log.save()
                    
                    if success:
                        results['sent'].append(email_address)
                        print(f"  ✓ Sent successfully to {email_address}")
                    else:
                        results['failed'].append(email_address)
                        print(f"  ✗ Failed to send to {email_address}")
                    
                    # No delay between emails - send as fast as possible within batch
                    
                except Exception as e:
                    print(f"  ✗ Error sending to {email_address}: {str(e)}")
                    # Create or update failed log entry
                    EmailLog.objects.update_or_create(
                        campaign=campaign,
                        recipient_email=email_address,
                        defaults={
                            'subject': campaign.subject,
                            'status': 'failed',
                            'error_message': str(e),
                            'sent_at': timezone.now()  # Explicit timestamp
                        }
                    )
                    results['failed'].append(email_address)
            
            # Check if campaign was paused before waiting for next batch
            campaign.refresh_from_db()
            if campaign.status != 'sending':
                print(f"\n⏸️  Campaign paused. Stopping email sending.")
                break
            
            # Wait before next batch (except after last batch)
            if batch_end < total:
                print(f"\n⏸️  Batch {batch_number} completed. Waiting {batch_delay} seconds before next batch...")
                # Check status during delay (check every 5 seconds)
                for _ in range(batch_delay // 5):
                    time.sleep(5)
                    campaign.refresh_from_db()
                    if campaign.status != 'sending':
                        print(f"\n⏸️  Campaign paused during delay. Stopping email sending.")
                        break
                else:
                    # If we didn't break, sleep the remaining time
                    remaining_time = batch_delay % 5
                    if remaining_time > 0:
                        time.sleep(remaining_time)
                        campaign.refresh_from_db()
                        if campaign.status != 'sending':
                            print(f"\n⏸️  Campaign paused during delay. Stopping email sending.")
                            break
        
        # Update campaign status based on results
        # Only mark as completed if still in 'sending' status (not paused)
        campaign.refresh_from_db()
        if campaign.status == 'sending':
            if results['sent'] or results['failed']:
                campaign.status = 'completed'
                campaign.sent_at = timezone.now()
                campaign.completed_at = timezone.now()  # Set exact completion time
                campaign.save()
        else:
            # Campaign was paused, keep it as 'draft'
            print(f"Campaign was paused, keeping status as '{campaign.status}'")
        
        print(f"Campaign restart completed: Sent: {len(results['sent'])}, Failed: {len(results['failed'])}")
        
        # Get final counts for accurate progress
        final_sent_count = len(results['sent'])
        final_failed_count = len(results['failed'])
        final_total = final_sent_count + final_failed_count
        
        return JsonResponse({
            'success': True,
            'message': f'Campaign restarted. Sent: {final_sent_count}, Failed: {final_failed_count}',
            'results': results,
            'total_emails': total_emails_to_send,
            'sent_count': final_sent_count,
            'failed_count': final_failed_count,
            'total_sent': final_total
        })
        
    except Campaign.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Campaign not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def pause_campaign(request, campaign_id):
    """API endpoint to pause a campaign"""
    try:
        campaign = Campaign.objects.get(id=campaign_id, created_by=request.user)
        # Allow pausing if status is 'sending' or 'completed' (to allow pausing after some emails sent)
        if campaign.status in ['sending', 'completed']:
            campaign.status = 'draft'
            campaign.save()
            return JsonResponse({
                'success': True,
                'message': 'Campaign paused successfully'
            })
        elif campaign.status == 'draft':
            return JsonResponse({
                'success': False,
                'error': 'Campaign is already paused'
            }, status=400)
        else:
            return JsonResponse({
                'success': False,
                'error': f'Cannot pause campaign with status: {campaign.status}'
            }, status=400)
    except Campaign.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Campaign not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def delete_campaign(request, campaign_id):
    """API endpoint to delete a campaign"""
    try:
        campaign = Campaign.objects.get(id=campaign_id, created_by=request.user)
        campaign_name = campaign.name
        campaign.delete()
        
        return JsonResponse({
            'success': True,
            'message': f'Campaign "{campaign_name}" deleted successfully'
        })
    except Campaign.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Campaign not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
def email_report(request):
    """Email report page - Only for users who can view all data"""
    # Check if user can view all data (not just staff/superuser)
    if not can_view_all_data(request.user):
        return redirect('dashboard')
    
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    user_filter = request.GET.get('user', '')
    campaign_filter = request.GET.get('campaign', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    # Start with all emails
    emails = EmailLog.objects.select_related('campaign', 'campaign__created_by').all()
    
    # Apply filters
    if status_filter:
        emails = emails.filter(status=status_filter)
    
    if user_filter:
        try:
            user_id = int(user_filter)
            emails = emails.filter(campaign__created_by_id=user_id)
        except (ValueError, TypeError):
            pass
    
    if campaign_filter:
        try:
            campaign_id = int(campaign_filter)
            emails = emails.filter(campaign_id=campaign_id)
        except (ValueError, TypeError):
            pass
    
    if date_from:
        try:
            from django.utils.dateparse import parse_date
            from datetime import datetime
            date_obj = parse_date(date_from)
            if date_obj:
                from django.utils import timezone
                emails = emails.filter(sent_at__gte=timezone.make_aware(
                    datetime.combine(date_obj, datetime.min.time())
                ))
        except Exception:
            pass
    
    if date_to:
        try:
            from django.utils.dateparse import parse_date
            from datetime import datetime
            date_obj = parse_date(date_to)
            if date_obj:
                from django.utils import timezone
                emails = emails.filter(sent_at__lte=timezone.make_aware(
                    datetime.combine(date_obj, datetime.max.time())
                ))
        except Exception:
            pass
    
    # Order by sent_at descending
    emails = emails.order_by('-sent_at')
    
    # Get statistics
    total_emails = emails.count()
    sent_count = emails.filter(status='sent').count()
    failed_count = emails.filter(status='failed').count()
    bounce_count = emails.filter(status='bounce').count()
    
    # Get all users for filter dropdown
    users = User.objects.all().order_by('username')
    
    # Get all campaigns for filter dropdown
    campaigns = Campaign.objects.all().order_by('-created_at')
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(emails, 50)  # Show 50 emails per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'emails': page_obj,
        'total_emails': total_emails,
        'sent_count': sent_count,
        'failed_count': failed_count,
        'bounce_count': bounce_count,
        'users': users,
        'campaigns': campaigns,
        'status_filter': status_filter,
        'user_filter': user_filter,
        'campaign_filter': campaign_filter,
        'date_from': date_from,
        'date_to': date_to,
    }
    
    return render(request, 'email_app/email_report.html', context)


@login_required
def campaign_report(request):
    """Campaign report page - Only for users who can view all data"""
    # Check if user can view all data (not just staff/superuser)
    if not can_view_all_data(request.user):
        return redirect('dashboard')
    
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    user_filter = request.GET.get('user', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    # Start with all campaigns
    campaigns = Campaign.objects.select_related('created_by').all()
    
    # Apply filters
    if status_filter:
        campaigns = campaigns.filter(status=status_filter)
    
    if user_filter:
        try:
            user_id = int(user_filter)
            campaigns = campaigns.filter(created_by_id=user_id)
        except (ValueError, TypeError):
            pass
    
    if date_from:
        try:
            from django.utils.dateparse import parse_date
            from datetime import datetime
            date_obj = parse_date(date_from)
            if date_obj:
                from django.utils import timezone
                campaigns = campaigns.filter(created_at__gte=timezone.make_aware(
                    datetime.combine(date_obj, datetime.min.time())
                ))
        except Exception:
            pass
    
    if date_to:
        try:
            from django.utils.dateparse import parse_date
            from datetime import datetime
            date_obj = parse_date(date_to)
            if date_obj:
                from django.utils import timezone
                campaigns = campaigns.filter(created_at__lte=timezone.make_aware(
                    datetime.combine(date_obj, datetime.max.time())
                ))
        except Exception:
            pass
    
    # Order by created_at descending
    campaigns = campaigns.order_by('-created_at')
    
    # Get statistics for each campaign
    from django.db.models import Count, Q
    campaigns_with_stats = []
    for campaign in campaigns:
        sent_count = EmailLog.objects.filter(campaign=campaign, status='sent').count()
        failed_count = EmailLog.objects.filter(campaign=campaign, status='failed').count()
        bounce_count = EmailLog.objects.filter(campaign=campaign, status='bounce').count()
        total_emails = sent_count + failed_count + bounce_count
        
        campaigns_with_stats.append({
            'campaign': campaign,
            'sent_count': sent_count,
            'failed_count': failed_count,
            'bounce_count': bounce_count,
            'total_emails': total_emails,
        })
    
    # Get overall statistics
    total_campaigns = len(campaigns_with_stats)
    completed_campaigns = campaigns.filter(status='completed').count()
    sending_campaigns = campaigns.filter(status='sending').count()
    draft_campaigns = campaigns.filter(status='draft').count()
    failed_campaigns = campaigns.filter(status='failed').count()
    
    # Get all users for filter dropdown
    users = User.objects.all().order_by('username')
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(campaigns_with_stats, 50)  # Show 50 campaigns per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'campaigns': page_obj,
        'total_campaigns': total_campaigns,
        'completed_campaigns': completed_campaigns,
        'sending_campaigns': sending_campaigns,
        'draft_campaigns': draft_campaigns,
        'failed_campaigns': failed_campaigns,
        'users': users,
        'status_filter': status_filter,
        'user_filter': user_filter,
        'date_from': date_from,
        'date_to': date_to,
    }
    
    return render(request, 'email_app/campaign_report.html', context)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def send_report_api(request):
    """API endpoint to send report via email - Admin only"""
    # Check if user is admin
    if not can_view_all_data(request.user):
        return JsonResponse({
            'success': False,
            'error': 'Permission denied'
        }, status=403)
    
    try:
        import json
        data = json.loads(request.body)
        recipient_email = data.get('email')
        report_type = data.get('report_type', 'campaign')
        filters = data.get('filters', {})
        
        if not recipient_email:
            return JsonResponse({
                'success': False,
                'error': 'Recipient email is required'
            }, status=400)
        
        # Get email credentials from session (same as send_email_api)
        gmail_username = request.session.get('gmail_username')
        gmail_password = request.session.get('gmail_password')
        gmail_port = request.session.get('gmail_port', 587)
        
        if gmail_username and gmail_password:
            smtp_username = gmail_username
            smtp_password = gmail_password
            smtp_server = 'smtp.gmail.com'
            smtp_port = gmail_port
        else:
            smtp_username = request.session.get('smtp_username') or settings.SENDER_EMAIL
            smtp_password = request.session.get('smtp_password') or settings.SENDER_PASSWORD
            smtp_server = 'mail.spacemail.com'
            smtp_port = 465
        
        if not smtp_username or not smtp_password:
            return JsonResponse({
                'success': False,
                'error': 'Please connect to SpaceMail or Gmail before sending reports'
            }, status=400)
        
        # Generate report content
        if report_type == 'campaign':
            # Get campaign data
            campaigns = Campaign.objects.select_related('created_by').all()
            
            # Apply filters
            if filters.get('status'):
                campaigns = campaigns.filter(status=filters['status'])
            if filters.get('user'):
                try:
                    campaigns = campaigns.filter(created_by_id=int(filters['user']))
                except (ValueError, TypeError):
                    pass
            
            # Build report HTML
            report_html = f"""
            <html>
            <head><style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style></head>
            <body>
                <h2>Campaign Report</h2>
                <p>Total Campaigns: {campaigns.count()}</p>
                <table>
                    <tr>
                        <th>Campaign Name</th>
                        <th>Subject</th>
                        <th>User</th>
                        <th>Status</th>
                        <th>Created At</th>
                    </tr>
            """
            for campaign in campaigns[:100]:  # Limit to 100 campaigns
                report_html += f"""
                    <tr>
                        <td>{campaign.name}</td>
                        <td>{campaign.subject[:50]}</td>
                        <td>{campaign.created_by.username if campaign.created_by else 'N/A'}</td>
                        <td>{campaign.status}</td>
                        <td>{campaign.created_at.strftime('%Y-%m-%d %H:%M')}</td>
                    </tr>
                """
            report_html += """
                </table>
            </body>
            </html>
            """
            subject = 'Campaign Report - SpaceMail'
        else:
            # Email report
            emails = EmailLog.objects.select_related('campaign', 'campaign__created_by').all()
            
            # Apply filters
            if filters.get('status'):
                emails = emails.filter(status=filters['status'])
            if filters.get('user'):
                try:
                    emails = emails.filter(campaign__created_by_id=int(filters['user']))
                except (ValueError, TypeError):
                    pass
            
            # Build report HTML
            report_html = f"""
            <html>
            <head><style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style></head>
            <body>
                <h2>Email Report</h2>
                <p>Total Emails: {emails.count()}</p>
                <table>
                    <tr>
                        <th>Recipient</th>
                        <th>Subject</th>
                        <th>Campaign</th>
                        <th>Status</th>
                        <th>Sent At</th>
                    </tr>
            """
            for email in emails[:100]:  # Limit to 100 emails
                report_html += f"""
                    <tr>
                        <td>{email.recipient_email}</td>
                        <td>{email.subject[:50]}</td>
                        <td>{email.campaign.name if email.campaign else 'N/A'}</td>
                        <td>{email.status}</td>
                        <td>{email.sent_at.strftime('%Y-%m-%d %H:%M')}</td>
                    </tr>
                """
            report_html += """
                </table>
            </body>
            </html>
            """
            subject = 'Email Report - SpaceMail'
        
        # Send email using EmailSender
        sender = EmailSender(
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            email=smtp_username,
            password=smtp_password
        )
        
        # Send HTML email using EmailSender
        success = sender.send_html_email(
            to_email=recipient_email,
            subject=subject,
            html_body=report_html
        )
        
        if success:
            return JsonResponse({
                'success': True,
                'message': 'Report sent successfully'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Failed to send email'
            }, status=500)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

