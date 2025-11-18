"""
URL configuration for email_automation project.
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from email_app.views import (
    dashboard, dashboard_api, campaign_emails_api, campaign_progress_api, email_details_api,
    send_email_page, send_email_api, parse_csv_columns, login_view, logout_view, signup_view,
    test_smtp_connection, spacemail_logout, test_gmail_connection, gmail_logout,
    check_bounces_api, get_bounces_api, restart_campaign, pause_campaign, delete_campaign, campaign_statistics_api,
    get_users_api, email_report, campaign_report, send_report_api, emails_by_status_api
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', dashboard, name='dashboard'),
    path('api/dashboard/', dashboard_api, name='dashboard_api'),
    path('api/users/', get_users_api, name='get_users_api'),
    path('api/check-bounces/', check_bounces_api, name='check_bounces_api'),
    path('api/get-bounces/', get_bounces_api, name='get_bounces_api'),
    path('api/email/<int:email_id>/details/', email_details_api, name='email_details_api'),
    path('api/campaign/<int:campaign_id>/emails/', campaign_emails_api, name='campaign_emails_api'),
    path('api/campaign/<int:campaign_id>/emails', campaign_emails_api, name='campaign_emails_api_no_slash'),  # Without trailing slash
    path('api/campaign/<int:campaign_id>/progress/', campaign_progress_api, name='campaign_progress_api'),
    path('api/campaign/<int:campaign_id>/statistics/', campaign_statistics_api, name='campaign_statistics_api'),
    path('api/campaign/<int:campaign_id>/statistics', campaign_statistics_api, name='campaign_statistics_api_no_slash'),  # Without trailing slash
    path('api/campaign/statistics/', campaign_statistics_api, name='overall_statistics_api'),
    path('send-email/', send_email_page, name='send_email_page'),
    path('api/send-email/', send_email_api, name='send_email_api'),
    path('api/parse-csv/', parse_csv_columns, name='parse_csv_columns'),
    path('api/test-smtp/', test_smtp_connection, name='test_smtp_connection'),
    path('api/test-gmail/', test_gmail_connection, name='test_gmail_connection'),
    path('api/spacemail-logout/', spacemail_logout, name='spacemail_logout'),
    path('api/gmail-logout/', gmail_logout, name='gmail_logout'),
    path('api/campaign/<int:campaign_id>/restart/', restart_campaign, name='restart_campaign'),
    path('api/campaign/<int:campaign_id>/pause/', pause_campaign, name='pause_campaign'),
    path('api/campaign/<int:campaign_id>/delete/', delete_campaign, name='delete_campaign'),
    path('login/', login_view, name='login'),
    path('signup/', signup_view, name='signup'),
    path('logout/', logout_view, name='logout'),
    path('email-report/', email_report, name='email_report'),
    path('campaign-report/', campaign_report, name='campaign_report'),
    path('api/send-report/', send_report_api, name='send_report_api'),
    path('api/emails-by-status/', emails_by_status_api, name='emails_by_status_api'),
]

# Serve static files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    # Also serve from STATICFILES_DIRS
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns
    urlpatterns += staticfiles_urlpatterns()

