"""
Email Sender Service for Practical DevSecOps
"""
import smtplib
import ssl
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from typing import List, Optional
import time
import csv
from django.conf import settings


class EmailSender:
    """Email automation for Practical DevSecOps campaigns"""
    
    def __init__(self, smtp_server: str = None, smtp_port: int = None, 
                 email: str = None, password: str = None):
        self.smtp_server = smtp_server or settings.SMTP_SERVER
        self.smtp_port = smtp_port or settings.SMTP_PORT
        self.email = email or settings.SENDER_EMAIL
        self.password = password or settings.SENDER_PASSWORD
        
        # Create SSL context - more flexible for production environments
        # Still validates certificates but allows for common issues
        self.context = ssl.create_default_context()
        # Don't verify hostname if certificate doesn't match (common with self-signed or internal certs)
        # But still verify the certificate chain
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE  # For production, you might want CERT_REQUIRED
    
    def _get_smtp_connection(self, timeout=30):
        """Get appropriate SMTP connection based on port"""
        if self.smtp_port == 465:
            # Port 465: Use SMTP_SSL (SSL/TLS from the start)
            return smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=self.context, timeout=timeout)
        elif self.smtp_port == 587:
            # Port 587: Use SMTP with STARTTLS
            # Create a wrapper to handle STARTTLS in context manager
            class SMTPWithSTARTTLSWrapper:
                def __init__(self, server, port, context, timeout):
                    self.server_host = server
                    self.server_port = port
                    self.context = context
                    self.timeout = timeout
                    self.server = None
                
                def __enter__(self):
                    self.server = smtplib.SMTP(self.server_host, self.server_port, timeout=self.timeout)
                    self.server.starttls(context=self.context)
                    return self.server
                
                def __exit__(self, exc_type, exc_val, exc_tb):
                    if self.server:
                        try:
                            self.server.quit()
                        except:
                            pass
                    return False
            
            return SMTPWithSTARTTLSWrapper(self.smtp_server, self.smtp_port, self.context, timeout)
        elif self.smtp_port == 25:
            # Port 25: Plain SMTP (no encryption)
            return smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=timeout)
        else:
            # Default: Try SMTP_SSL for other ports
            return smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=self.context, timeout=timeout)
    
    def test_connection(self, retries=2) -> dict:
        """Test SMTP connection with better error handling and retry logic"""
        # Check if credentials are set
        if not self.email:
            return {'success': False, 'error': 'Email/Sender not configured. Please set SENDER_EMAIL environment variable.'}
        if not self.password:
            return {'success': False, 'error': 'Password not configured. Please set SENDER_PASSWORD environment variable.'}
        if not self.smtp_server:
            return {'success': False, 'error': 'SMTP server not configured. Please set SMTP_SERVER environment variable.'}
        
        # First, test if we can reach the server (DNS and network connectivity)
        try:
            # Set socket timeout for DNS lookup and connection
            socket.setdefaulttimeout(10)
            test_socket = socket.create_connection((self.smtp_server, self.smtp_port), timeout=10)
            test_socket.close()
        except socket.timeout:
            return {'success': False, 'error': f'Connection timeout: Cannot reach {self.smtp_server}:{self.smtp_port}. The server may be down, or your network/firewall is blocking the connection.'}
        except socket.gaierror as e:
            return {'success': False, 'error': f'DNS Error: Cannot resolve {self.smtp_server}. Check if the server address is correct.'}
        except OSError as e:
            return {'success': False, 'error': f'Network Error: Cannot connect to {self.smtp_server}:{self.smtp_port}. {str(e)}. Check firewall settings and network connectivity.'}
        except Exception as e:
            return {'success': False, 'error': f'Connection test failed: {str(e)}'}
        finally:
            socket.setdefaulttimeout(None)  # Reset to default
        
        # Now try SMTP connection with retries
        last_error = None
        for attempt in range(retries + 1):
            try:
                # Reduced timeout for faster response (15 seconds per attempt)
                # This helps avoid Render's 30-second request timeout
                with self._get_smtp_connection(timeout=15) as server:
                    server.login(self.email, self.password)
                return {'success': True, 'message': f'Connection successful to {self.smtp_server}:{self.smtp_port}!'}
            except socket.timeout:
                last_error = f'Connection timeout after 15 seconds. The SMTP server is not responding quickly enough.'
                if attempt < retries:
                    time.sleep(1)  # Wait 1 second before retry
                    continue
            except ssl.SSLError as e:
                return {'success': False, 'error': f'SSL Error: {str(e)}. Check if port {self.smtp_port} is correct and server supports SSL/TLS.'}
            except smtplib.SMTPAuthenticationError as e:
                error_msg = str(e)
                # Provide helpful guidance for Gmail authentication errors
                if 'gmail.com' in self.smtp_server.lower() or 'BadCredentials' in error_msg or 'gsmtp' in error_msg.lower():
                    return {
                        'success': False, 
                        'error': 'Gmail authentication failed. You must use an App Password (not your regular password). Enable 2-Step Verification and generate an App Password at https://myaccount.google.com/apppasswords'
                    }
                return {'success': False, 'error': f'Authentication failed: {str(e)}. Check your email and password.'}
            except smtplib.SMTPConnectError as e:
                last_error = f'SMTP Connection failed: {str(e)}. Check if {self.smtp_server} is reachable and port {self.smtp_port} is open.'
                if attempt < retries:
                    time.sleep(1)
                    continue
            except smtplib.SMTPException as e:
                return {'success': False, 'error': f'SMTP Error: {str(e)}'}
            except OSError as e:
                last_error = f'Network Error: {str(e)}. Check network connectivity and firewall settings. From production, ensure outbound connections to port {self.smtp_port} are allowed.'
                if attempt < retries:
                    time.sleep(1)
                    continue
            except Exception as e:
                return {'success': False, 'error': f'Unexpected error: {str(e)}'}
        
        # If we get here, all retries failed
        return {'success': False, 'error': last_error or 'Connection failed after multiple attempts.'}
    
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
            
            # Use appropriate connection method based on port
            with self._get_smtp_connection(timeout=30) as server:
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
            
            # Use appropriate connection method based on port
            with self._get_smtp_connection(timeout=30) as server:
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
            
            # Use appropriate connection method based on port
            with self._get_smtp_connection(timeout=30) as server:
                server.login(self.email, self.password)
                server.send_message(message)
            
            print(f"✓ Email with attachment sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to send email with attachment to {to_email}: {str(e)}")
            return False
    
    def _safe_format_template(self, template: str, data: dict) -> str:
        """Safely format template string with case-insensitive attribute matching"""
        import re
        
        if not data:
            return template
        
        # Normalize data keys - create lookup dict with all variations
        lookup = {}
        for key, value in data.items():
            if key:
                key_str = str(key).strip()
                val_str = str(value).strip() if value is not None and value != '' else ''
                
                # Store original key
                lookup[key_str] = val_str
                
                # Store lowercase version
                lookup[key_str.lower()] = val_str
                
                # Store normalized version (spaces -> underscores)
                normalized = normalize_column_name(key_str)
                if normalized and normalized != key_str.lower():
                    lookup[normalized] = val_str
                
                # Store with spaces replaced by underscores
                underscore_version = key_str.replace(' ', '_').replace('-', '_')
                if underscore_version != key_str:
                    lookup[underscore_version] = val_str
                    lookup[underscore_version.lower()] = val_str
        
        # Find all placeholders in the template like {key}
        pattern = r'\{([^}]+)\}'
        
        def replace_placeholder(match):
            placeholder = match.group(1).strip()
            placeholder_lower = placeholder.lower()
            placeholder_normalized = normalize_column_name(placeholder)
            placeholder_underscore = placeholder.replace(' ', '_').replace('-', '_').lower()
            
            # Try exact match first
            if placeholder in lookup:
                return lookup[placeholder]
            
            # Try lowercase match
            if placeholder_lower in lookup:
                return lookup[placeholder_lower]
            
            # Try normalized match (spaces -> underscores)
            if placeholder_normalized in lookup:
                return lookup[placeholder_normalized]
            
            # Try underscore version
            if placeholder_underscore in lookup:
                return lookup[placeholder_underscore]
            
            # Try to find any key that matches (case-insensitive, space-insensitive)
            for key, value in data.items():
                if key:
                    key_str = str(key).strip()
                    key_normalized = normalize_column_name(key_str)
                    
                    # Check various matching conditions
                    if (key_str.lower() == placeholder_lower or
                        key_normalized == placeholder_normalized or
                        key_normalized == placeholder_underscore or
                        key_str.lower().replace(' ', '_') == placeholder_underscore):
                        return str(value).strip() if value is not None and value != '' else ''
            
            # If not found, return the original placeholder
            return match.group(0)
        
        # Replace all placeholders
        result = re.sub(pattern, replace_placeholder, template)
        
        return result
    
    def _get_email_from_recipient(self, recipient: dict) -> Optional[str]:
        """Get email from recipient dict with case-insensitive matching"""
        # Try exact matches first
        email_keys = ['email', 'Email', 'EMAIL', 'e-mail', 'E-mail', 'E-Mail', 'mail', 'Mail', 'MAIL']
        for key in email_keys:
            if key in recipient and recipient[key]:
                email = str(recipient[key]).strip()
                if email and '@' in email:
                    return email
        
        # Try case-insensitive search
        recipient_lower = {k.lower(): v for k, v in recipient.items()}
        for key, value in recipient_lower.items():
            if 'email' in key or 'mail' in key:
                email = str(value).strip()
                if email and '@' in email:
                    return email
        
        # Last resort: find any value that looks like an email
        for key, value in recipient.items():
            if value and isinstance(value, str) and '@' in value and '.' in value:
                email = value.strip()
                if email:
                    return email
        
        return None
    
    def send_bulk_emails(self,
                        recipients: List[dict],
                        subject_template: str,
                        body_template: str,
                        is_html: bool = False,
                        delay: float = 1.5,
                        default_attributes: dict = None) -> dict:
        """Send bulk personalized emails"""
        results = {'sent': [], 'failed': []}
        total = len(recipients)
        
        print(f"\n📧 Starting bulk email campaign...")
        print(f"Total recipients: {total}")
        print(f"Delay between emails: {delay}s\n")
        
        for i, recipient in enumerate(recipients, 1):
            try:
                # Normalize recipient keys to lowercase for easier access
                normalized_recipient = {k.lower(): v for k, v in recipient.items()}
                normalized_recipient.update(recipient)  # Keep original keys too
                
                # Merge with default attributes (manual attributes from form)
                # CSV data takes precedence over default attributes
                if default_attributes:
                    # Add defaults first, then CSV data will override
                    merged_data = {**default_attributes, **normalized_recipient}
                    # Also add lowercase versions
                    merged_data.update({k.lower(): v for k, v in merged_data.items()})
                else:
                    merged_data = normalized_recipient
                
                # Debug: Print recipient data
                print(f"  📋 Recipient data keys: {list(merged_data.keys())}")
                print(f"  📋 Sample values: first_name={merged_data.get('first_name', 'NOT FOUND')}, company={merged_data.get('company', 'NOT FOUND')}")
                
                # Format templates safely with merged data
                subject = self._safe_format_template(subject_template, merged_data)
                body = self._safe_format_template(body_template, merged_data)
                
                # Debug: Show formatted result
                print(f"  📝 Formatted subject: {subject[:50]}...")
                print(f"  📝 Formatted body preview: {body[:100]}...")
                
                # Get email with case-insensitive matching
                to_email = self._get_email_from_recipient(recipient)
                
                if not to_email:
                    print(f"[{i}/{total}] ✗ No email found in recipient data")
                    results['failed'].append('unknown')
                    continue
                
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
                email = self._get_email_from_recipient(recipient) or 'unknown'
                results['failed'].append(email)
        
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
            
            # Use appropriate connection method based on port
            with self._get_smtp_connection(timeout=30) as server:
                server.login(self.email, self.password)
                server.send_message(message)
            
            print(f"✓ Threaded email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to send threaded email to {to_email}: {str(e)}")
            return False


def normalize_column_name(col_name: str) -> str:
    """Normalize column name to handle spaces and different cases"""
    if not col_name:
        return ''
    # Convert to lowercase and replace spaces with underscores
    normalized = col_name.strip().lower().replace(' ', '_').replace('-', '_')
    return normalized

def load_recipients_from_csv(csv_file: str) -> List[dict]:
    """Load recipients from CSV file"""
    recipients = []
    try:
        with open(csv_file, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            columns = reader.fieldnames
            if columns:
                print(f"📋 CSV Columns detected: {', '.join(columns)}")
            for row in reader:
                # Clean up the row - create both original and normalized keys
                cleaned_row = {}
                for key, value in row.items():
                    if value is not None:
                        cleaned_value = value.strip() if isinstance(value, str) else value
                    else:
                        cleaned_value = ''
                    
                    # Store with original key
                    cleaned_row[key] = cleaned_value
                    # Also store with normalized key (spaces -> underscores, lowercase)
                    normalized_key = normalize_column_name(key)
                    if normalized_key and normalized_key != key.lower():
                        cleaned_row[normalized_key] = cleaned_value
                    # Store lowercase version of original
                    cleaned_row[key.lower()] = cleaned_value
                
                recipients.append(cleaned_row)
        print(f"✓ Loaded {len(recipients)} recipients from {csv_file}")
        if recipients:
            print(f"📋 Sample row keys: {list(recipients[0].keys())}")
        return recipients
    except Exception as e:
        print(f"✗ Error loading CSV: {str(e)}")
        return []

