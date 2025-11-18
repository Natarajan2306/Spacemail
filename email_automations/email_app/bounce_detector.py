"""
Bounce Detection Service for SpaceMail
Monitors email inbox for bounce messages and updates EmailLog status
"""
import imaplib
import email
import re
from email.header import decode_header
from typing import List, Dict, Optional
from django.conf import settings
from django.utils import timezone
from email_app.models import EmailLog, BounceRecord
import ssl


class BounceDetector:
    """Detect email bounces by monitoring IMAP inbox"""
    
    def __init__(self, imap_server: str = None, imap_port: int = None,
                 email: str = None, password: str = None):
        self.imap_server = imap_server or getattr(settings, 'IMAP_SERVER', None) or settings.SMTP_SERVER
        self.imap_port = imap_port or getattr(settings, 'IMAP_PORT', 993)
        self.email = email or settings.SENDER_EMAIL
        self.password = password or settings.SENDER_PASSWORD
        self.context = ssl.create_default_context()
    
    def connect(self) -> Optional[imaplib.IMAP4_SSL]:
        """Connect to IMAP server"""
        try:
            mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port, ssl_context=self.context)
            mail.login(self.email, self.password)
            return mail
        except Exception as e:
            print(f"✗ Failed to connect to IMAP server: {str(e)}")
            return None
    
    def decode_mime_words(self, s: str) -> str:
        """Decode MIME encoded words in email headers"""
        decoded_parts = decode_header(s)
        decoded_str = ''
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                decoded_str += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                decoded_str += part
        return decoded_str
    
    def extract_email_from_bounce(self, bounce_body: str) -> Optional[str]:
        """Extract original recipient email from bounce message"""
        # Common bounce patterns
        patterns = [
            r'To:\s*([^\s<]+@[^\s>]+)',  # To: email@domain.com
            r'Original-Recipient:\s*([^\s<]+@[^\s>]+)',  # Original-Recipient: email@domain.com
            r'Final-Recipient:\s*([^\s<]+@[^\s>]+)',  # Final-Recipient: email@domain.com
            r'<([^\s<>]+@[^\s<>]+)>',  # <email@domain.com>
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # Generic email pattern
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, bounce_body, re.IGNORECASE)
            if matches:
                # Filter out common bounce addresses
                for match in matches:
                    email_addr = match.strip()
                    if email_addr and '@' in email_addr:
                        # Skip common bounce/mailer-daemon addresses
                        if not any(skip in email_addr.lower() for skip in [
                            'mailer-daemon', 'postmaster', 'noreply', 'no-reply',
                            'bounce', 'return', 'undeliverable'
                        ]):
                            return email_addr
        
        return None
    
    def is_bounce_message(self, msg: email.message.Message) -> bool:
        """Check if message is a bounce notification"""
        subject = self.decode_mime_words(msg.get('Subject', '') or '')
        from_addr = msg.get('From', '').lower()
        
        # Check subject for bounce indicators
        bounce_subject_keywords = [
            'undeliverable', 'delivery failure', 'delivery status',
            'mail delivery failed', 'returned mail', 'failure notice',
            'delivery error', 'bounce', 'undelivered', 'mailer-daemon'
        ]
        
        subject_lower = subject.lower()
        if any(keyword in subject_lower for keyword in bounce_subject_keywords):
            return True
        
        # Check From address
        if any(keyword in from_addr for keyword in [
            'mailer-daemon', 'postmaster', 'mail delivery', 'bounce'
        ]):
            return True
        
        return False
    
    def parse_bounce_message(self, msg: email.message.Message) -> Dict:
        """Parse bounce message to extract information"""
        bounce_info = {
            'is_bounce': False,
            'recipient_email': None,
            'bounce_reason': '',
            'subject': '',
            'from_addr': ''
        }
        
        if not self.is_bounce_message(msg):
            return bounce_info
        
        bounce_info['is_bounce'] = True
        bounce_info['subject'] = self.decode_mime_words(msg.get('Subject', '') or '')
        bounce_info['from_addr'] = msg.get('From', '')
        
        # Get email body
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode('utf-8', errors='ignore')
            except:
                pass
        
        # Extract recipient email
        recipient = self.extract_email_from_bounce(body)
        if recipient:
            bounce_info['recipient_email'] = recipient.lower()
        
        # Extract bounce reason
        reason_patterns = [
            r'Reason:\s*(.+?)(?:\n|$)',
            r'Diagnostic-Code:\s*(.+?)(?:\n|$)',
            r'Status:\s*(.+?)(?:\n|$)',
        ]
        
        for pattern in reason_patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
            if match:
                bounce_info['bounce_reason'] = match.group(1).strip()[:500]
                break
        
        if not bounce_info['bounce_reason']:
            bounce_info['bounce_reason'] = bounce_info['subject'][:500]
        
        return bounce_info
    
    def check_bounces(self, mailbox: str = 'INBOX', limit: int = 200) -> List[Dict]:
        """Check for bounce messages in mailbox - checks ALL emails, not just unread"""
        mail = self.connect()
        if not mail:
            return []
        
        bounces_found = []
        
        try:
            # Select mailbox
            mail.select(mailbox)
            
            # Search for ALL messages in the mailbox (not just unread)
            # This will find all bounce emails regardless of read status
            status, messages = mail.search(None, 'ALL')
            
            if status != 'OK':
                print("✗ Failed to search mailbox")
                mail.close()
                mail.logout()
                return []
            
            email_ids = messages[0].split()
            
            # Limit the number of emails to check (check most recent first)
            if len(email_ids) > limit:
                # Take the most recent emails (last ones in the list)
                email_ids = email_ids[-limit:]
            
            print(f"📧 Checking {len(email_ids)} messages for bounces...")
            
            for email_id in email_ids:
                try:
                    # Fetch email
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    
                    if status != 'OK':
                        continue
                    
                    # Parse email
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    # Check if it's a bounce
                    bounce_info = self.parse_bounce_message(msg)
                    
                    if bounce_info['is_bounce'] and bounce_info['recipient_email']:
                        bounces_found.append({
                            'email_id': email_id.decode(),
                            'recipient_email': bounce_info['recipient_email'],
                            'bounce_reason': bounce_info['bounce_reason'],
                            'subject': bounce_info['subject'],
                            'from_addr': bounce_info['from_addr']
                        })
                        print(f"  ✓ Bounce detected for: {bounce_info['recipient_email']}")
                
                except Exception as e:
                    print(f"  ✗ Error processing email {email_id}: {str(e)}")
                    continue
            
            mail.close()
            mail.logout()
            
        except Exception as e:
            print(f"✗ Error checking bounces: {str(e)}")
            try:
                mail.close()
                mail.logout()
            except:
                pass
        
        return bounces_found
    
    def update_bounce_status(self, bounces: List[Dict], user=None) -> Dict:
        """Update EmailLog status to 'bounce' for bounced emails and create BounceRecord for all
        
        Args:
            bounces: List of bounce dictionaries
            user: Optional user to filter EmailLog entries by (only update emails from this user's campaigns)
                  If None, updates any EmailLog entry (for admin viewing all data)
        """
        updated_count = 0
        not_found_count = 0
        
        for bounce in bounces:
            recipient_email = bounce['recipient_email']
            email_log = None
            
            # Find EmailLog entries for this recipient (case-insensitive)
            # Update the most recent 'sent' status email
            # If user is provided, only update emails from that user's campaigns
            email_logs = EmailLog.objects.filter(
                recipient_email__iexact=recipient_email,
                status='sent'
            )
            
            # Filter by user's campaigns if user is provided
            if user:
                email_logs = email_logs.filter(campaign__created_by=user)
            
            email_logs = email_logs.order_by('-sent_at')
            
            if email_logs.exists():
                # Update the most recent one
                email_log = email_logs.first()
                email_log.status = 'bounce'
                email_log.error_message = bounce['bounce_reason']
                email_log.save()
                updated_count += 1
                if user:
                    print(f"  ✓ Updated status to 'bounce' for {recipient_email} (user: {user.username})")
                else:
                    print(f"  ✓ Updated status to 'bounce' for {recipient_email}")
            else:
                not_found_count += 1
                if user:
                    print(f"  ⚠ No 'sent' EmailLog found for {recipient_email} (user: {user.username})")
                else:
                    print(f"  ⚠ No 'sent' EmailLog found for {recipient_email}")
            
            # Create BounceRecord for ALL bounces (matched and unmatched)
            # This allows us to count all bounce emails found
            try:
                # Check if bounce record exists for this email (within last 24 hours to avoid duplicates)
                from datetime import timedelta
                recent_cutoff = timezone.now() - timedelta(hours=24)
                existing_record = BounceRecord.objects.filter(
                    recipient_email__iexact=recipient_email,
                    detected_at__gte=recent_cutoff
                ).first()
                
                if not existing_record:
                    BounceRecord.objects.create(
                        recipient_email=recipient_email,
                        subject=bounce.get('subject', '')[:500],
                        bounce_reason=bounce.get('bounce_reason', '')[:500],
                        from_addr=bounce.get('from_addr', '')[:500],
                        email_log=email_log
                    )
            except Exception as e:
                # If BounceRecord model doesn't exist yet (migration not run), skip
                print(f"  ⚠ Could not create BounceRecord: {str(e)}")
        
        return {
            'updated': updated_count,
            'not_found': not_found_count,
            'total_bounces': len(bounces)
        }

