#!/usr/bin/env python3
"""
Email Automation Script - Practical DevSecOps
Configured for: natty@pdesolearn.com
Server: mail.spacemail.com (SSL on port 465)
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from typing import List, Optional
import time
import csv

# ============================================
# SMTP CONFIGURATION - CORRECTED
# ============================================

SMTP_SERVER = 'mail.spacemail.com'
SMTP_PORT = 465  # SSL port
SENDER_EMAIL = 'natty@pdsolearn.com'
SENDER_PASSWORD = '028a9c30-66Ff-41dB-bdfa-2301D25A49b2'

# ============================================
# EMAIL SENDER CLASS
# ============================================

class EmailSender:
    """Email automation for Practical DevSecOps campaigns"""
    
    def __init__(self, smtp_server: str, smtp_port: int, email: str, password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.email = email
        self.password = password
        self.context = ssl.create_default_context()
    
    def send_simple_email(self, 
                         to_email: str, 
                         subject: str, 
                         body: str,
                         cc: Optional[List[str]] = None,
                         bcc: Optional[List[str]] = None) -> bool:
        """Send a simple text email"""
        try:
            message = MIMEMultipart()
            message['From'] = self.email
            message['To'] = to_email
            message['Subject'] = subject
            
            if cc:
                message['Cc'] = ', '.join(cc)
            
            message.attach(MIMEText(body, 'plain'))
            
            recipients = [to_email]
            if cc:
                recipients.extend(cc)
            if bcc:
                recipients.extend(bcc)
            
            # Use SMTP_SSL for port 465
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=self.context) as server:
                server.login(self.email, self.password)
                server.send_message(message, to_addrs=recipients)
            
            print(f"✓ Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to send email to {to_email}: {str(e)}")
            return False
    
    def send_html_email(self,
                       to_email: str,
                       subject: str,
                       html_body: str,
                       plain_text_fallback: Optional[str] = None,
                       cc: Optional[List[str]] = None,
                       bcc: Optional[List[str]] = None) -> bool:
        """Send an HTML email"""
        try:
            message = MIMEMultipart('alternative')
            message['From'] = self.email
            message['To'] = to_email
            message['Subject'] = subject
            
            if cc:
                message['Cc'] = ', '.join(cc)
            
            if plain_text_fallback:
                text_part = MIMEText(plain_text_fallback, 'plain')
                message.attach(text_part)
            
            html_part = MIMEText(html_body, 'html')
            message.attach(html_part)
            
            recipients = [to_email]
            if cc:
                recipients.extend(cc)
            if bcc:
                recipients.extend(bcc)
            
            # Use SMTP_SSL for port 465
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=self.context) as server:
                server.login(self.email, self.password)
                server.send_message(message, to_addrs=recipients)
            
            print(f"✓ HTML email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to send HTML email to {to_email}: {str(e)}")
            return False
    
    def send_email_with_attachment(self,
                                   to_email: str,
                                   subject: str,
                                   body: str,
                                   attachment_path: str,
                                   is_html: bool = False) -> bool:
        """Send an email with attachment"""
        try:
            message = MIMEMultipart()
            message['From'] = self.email
            message['To'] = to_email
            message['Subject'] = subject
            
            body_type = 'html' if is_html else 'plain'
            message.attach(MIMEText(body, body_type))
            
            if os.path.exists(attachment_path):
                with open(attachment_path, 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                encoders.encode_base64(part)
                filename = os.path.basename(attachment_path)
                part.add_header('Content-Disposition', f'attachment; filename= {filename}')
                message.attach(part)
            else:
                print(f"Warning: Attachment file not found: {attachment_path}")
            
            # Use SMTP_SSL for port 465
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=self.context) as server:
                server.login(self.email, self.password)
                server.send_message(message)
            
            print(f"✓ Email with attachment sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to send email with attachment to {to_email}: {str(e)}")
            return False
    
    def send_bulk_emails(self,
                        recipients: List[dict],
                        subject_template: str,
                        body_template: str,
                        is_html: bool = False,
                        delay: float = 1.5) -> dict:
        """Send bulk personalized emails"""
        results = {'sent': [], 'failed': []}
        total = len(recipients)
        
        print(f"\n📧 Starting bulk email campaign...")
        print(f"Total recipients: {total}")
        print(f"Delay between emails: {delay}s\n")
        
        for i, recipient in enumerate(recipients, 1):
            try:
                subject = subject_template.format(**recipient)
                body = body_template.format(**recipient)
                to_email = recipient['email']
                
                print(f"[{i}/{total}] Sending to {to_email}...", end=" ")
                
                if is_html:
                    success = self.send_html_email(to_email, subject, body)
                else:
                    success = self.send_simple_email(to_email, subject, body)
                
                if success:
                    results['sent'].append(to_email)
                else:
                    results['failed'].append(to_email)
                
                if i < total:
                    time.sleep(delay)
                    
            except Exception as e:
                print(f"✗ Error: {str(e)}")
                results['failed'].append(recipient.get('email', 'unknown'))
        
        print(f"\n{'='*60}")
        print(f"📊 Campaign Summary:")
        print(f"   Successfully sent: {len(results['sent'])}")
        print(f"   Failed: {len(results['failed'])}")
        print(f"{'='*60}\n")
        
        return results
    
    def send_threaded_email(self,
                           to_email: str,
                           subject: str,
                           body: str,
                           thread_id: str,
                           is_html: bool = False) -> bool:
        """Send an email as part of a thread"""
        try:
            message = MIMEMultipart()
            message['From'] = self.email
            message['To'] = to_email
            message['Subject'] = subject
            message['In-Reply-To'] = thread_id
            message['References'] = thread_id
            
            body_type = 'html' if is_html else 'plain'
            message.attach(MIMEText(body, body_type))
            
            # Use SMTP_SSL for port 465
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=self.context) as server:
                server.login(self.email, self.password)
                server.send_message(message)
            
            print(f"✓ Threaded email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to send threaded email to {to_email}: {str(e)}")
            return False

# ============================================
# UTILITY FUNCTIONS
# ============================================

def load_recipients_from_csv(csv_file: str) -> List[dict]:
    """Load recipients from CSV file"""
    recipients = []
    try:
        with open(csv_file, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                recipients.append(row)
        print(f"✓ Loaded {len(recipients)} recipients from {csv_file}")
        return recipients
    except Exception as e:
        print(f"✗ Error loading CSV: {str(e)}")
        return []

# ============================================
# MAIN SCRIPT
# ============================================

def main():
    """Main function - Send email"""
    
    # Initialize email sender
    sender = EmailSender(
        smtp_server=SMTP_SERVER,
        smtp_port=SMTP_PORT,
        email=SENDER_EMAIL,
        password=SENDER_PASSWORD
    )
    
    # Send email
    sender.send_simple_email(
        to_email='natty@pdevsecops.com',
        subject='Test Email - Python Script',
        body='This is a test email from the Python automation script.\n\nServer: mail.spacemail.com\nPort: 465 (SSL)',
        cc=['Natarajan@pdevsecops.com']
    )

if __name__ == "__main__":
    main()