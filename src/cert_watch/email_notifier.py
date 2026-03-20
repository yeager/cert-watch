"""Email notification system for certificate expiry warnings."""
import smtplib
import ssl as ssl_module
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Email notification system for sending certificate expiry warnings."""
    
    def __init__(self, config=None):
        """Initialize with email configuration.
        
        Args:
            config: Dictionary containing email settings:
                - smtp_server: SMTP server hostname
                - smtp_port: SMTP server port (default 587)
                - smtp_user: SMTP username/email
                - smtp_password: SMTP password
                - use_tls: Whether to use TLS (default True)
                - from_email: From email address
                - to_emails: List of recipient email addresses
                - warning_days: List of days before expiry to send warnings (default [7, 3, 1])
        """
        self.config = config or {}
        self.warning_days = self.config.get('warning_days', [7, 3, 1])
    
    def is_configured(self):
        """Check if email notifications are properly configured."""
        required_fields = ['smtp_server', 'smtp_user', 'smtp_password', 'from_email', 'to_emails']
        return all(self.config.get(field) for field in required_fields)
    
    def should_send_warning(self, cert_info, last_notifications=None):
        """Check if we should send a warning for this certificate.
        
        Args:
            cert_info: Certificate information dictionary
            last_notifications: Dict of last notification timestamps by domain
            
        Returns:
            Tuple of (should_send, warning_type) where warning_type is days until expiry
        """
        if not self.is_configured():
            return False, None
            
        if cert_info.get('error'):
            return False, None
            
        days_left = cert_info.get('days_left')
        if days_left is None:
            return False, None
            
        domain = cert_info['domain']
        last_notifications = last_notifications or {}
        
        # Check if we should send a warning for any of the warning thresholds
        for warning_days in sorted(self.warning_days, reverse=True):
            if days_left <= warning_days:
                # Check if we already sent this warning recently (within last 23 hours)
                last_key = f"{domain}_{warning_days}d"
                last_sent = last_notifications.get(last_key)
                
                if last_sent:
                    try:
                        last_dt = datetime.fromisoformat(last_sent)
                        hours_since = (datetime.now() - last_dt).total_seconds() / 3600
                        if hours_since < 23:
                            continue  # Already sent recently
                    except (ValueError, TypeError):
                        pass  # Invalid timestamp, proceed to send
                
                return True, warning_days
        
        return False, None
    
    def send_warning(self, cert_info, warning_days):
        """Send certificate expiry warning email.
        
        Args:
            cert_info: Certificate information dictionary
            warning_days: Number of days until expiry that triggered this warning
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if not self.is_configured():
            logger.warning("Email notifications not configured")
            return False
            
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config['from_email']
            msg['To'] = ', '.join(self.config['to_emails'])
            
            domain = cert_info['domain']
            days_left = cert_info.get('days_left', '?')
            
            if warning_days == 1:
                urgency = "🚨 URGENT"
                subject = f"🚨 Certificate expires TOMORROW: {domain}"
            elif warning_days <= 3:
                urgency = "⚠️ WARNING"
                subject = f"⚠️ Certificate expires in {days_left} days: {domain}"
            else:
                urgency = "📋 NOTICE"
                subject = f"📋 Certificate expires in {days_left} days: {domain}"
                
            msg['Subject'] = subject
            
            # Create email body
            body = self._create_email_body(cert_info, urgency)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(
                self.config['smtp_server'], 
                self.config.get('smtp_port', 587)
            )
            
            if self.config.get('use_tls', True):
                server.starttls(context=ssl_module.create_default_context())
                
            server.login(self.config['smtp_user'], self.config['smtp_password'])
            
            text = msg.as_string()
            server.sendmail(
                self.config['from_email'], 
                self.config['to_emails'], 
                text
            )
            server.quit()
            
            logger.info(f"Email warning sent for {domain} ({days_left} days left)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email warning for {domain}: {e}")
            return False
    
    def _create_email_body(self, cert_info, urgency):
        """Create HTML email body for certificate warning.
        
        Args:
            cert_info: Certificate information dictionary
            urgency: Urgency level string
            
        Returns:
            str: HTML email body
        """
        domain = cert_info['domain']
        days_left = cert_info.get('days_left', '?')
        issuer = cert_info.get('issuer', {}).get('organizationName', 
                cert_info.get('issuer', {}).get('commonName', 'Unknown'))
        not_after = cert_info.get('not_after', 'Unknown')
        protocol = cert_info.get('protocol', 'Unknown')
        
        color = "#dc2626" if days_left <= 1 else "#ea580c" if days_left <= 3 else "#2563eb"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8fafc; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
                .header {{ background: {color}; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .warning-box {{ background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 15px; margin: 15px 0; }}
                .detail-row {{ margin: 8px 0; }}
                .label {{ font-weight: 600; color: #374151; }}
                .value {{ color: #6b7280; }}
                .footer {{ background: #f9fafb; padding: 15px; text-align: center; color: #6b7280; font-size: 12px; }}
                .action-button {{ display: inline-block; background: {color}; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0; font-size: 20px;">{urgency}</h1>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">TLS Certificate Expiry Warning</p>
                </div>
                
                <div class="content">
                    <div class="warning-box">
                        <h2 style="margin: 0 0 10px 0; color: {color};">Certificate Expires in {days_left} Day{'s' if days_left != 1 else ''}</h2>
                        <p style="margin: 0;"><strong>Domain:</strong> {domain}</p>
                    </div>
                    
                    <h3>Certificate Details</h3>
                    <div class="detail-row">
                        <span class="label">Domain:</span> <span class="value">{domain}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Issuer:</span> <span class="value">{issuer}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Expires:</span> <span class="value">{not_after}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Days Remaining:</span> <span class="value">{days_left}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Protocol:</span> <span class="value">{protocol}</span>
                    </div>
                    
                    <h3>Recommended Action</h3>
                    <p>Please renew the TLS certificate for <strong>{domain}</strong> as soon as possible to avoid service disruption.</p>
                    
                    <p>This notification was generated automatically by Cert Watch.</p>
                </div>
                
                <div class="footer">
                    <p>Cert Watch | TLS Certificate Monitor</p>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """


def send_error_notification(config, domain, error_message):
    """Send notification for certificate check errors.
    
    Args:
        config: Email configuration dictionary
        domain: Domain that failed
        error_message: Error message
        
    Returns:
        bool: True if email was sent successfully
    """
    notifier = EmailNotifier(config)
    if not notifier.is_configured():
        return False
        
    try:
        msg = MIMEMultipart()
        msg['From'] = config['from_email']
        msg['To'] = ', '.join(config['to_emails'])
        msg['Subject'] = f"🚫 Certificate Check Failed: {domain}"
        
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8fafc; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
                .header {{ background: #dc2626; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .error-box {{ background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 15px; margin: 15px 0; }}
                .footer {{ background: #f9fafb; padding: 15px; text-align: center; color: #6b7280; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0; font-size: 20px;">🚫 CERTIFICATE CHECK FAILED</h1>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">Unable to check certificate status</p>
                </div>
                
                <div class="content">
                    <div class="error-box">
                        <h2 style="margin: 0 0 10px 0; color: #dc2626;">Check Failed for {domain}</h2>
                        <p style="margin: 0;"><strong>Error:</strong> {error_message}</p>
                    </div>
                    
                    <p>Cert Watch was unable to retrieve certificate information for <strong>{domain}</strong>.</p>
                    <p>Please check:</p>
                    <ul>
                        <li>Domain is accessible from your network</li>
                        <li>Certificate is properly configured</li>
                        <li>No firewall or DNS issues</li>
                    </ul>
                </div>
                
                <div class="footer">
                    <p>Cert Watch | TLS Certificate Monitor</p>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email using same logic as EmailNotifier
        server = smtplib.SMTP(config['smtp_server'], config.get('smtp_port', 587))
        if config.get('use_tls', True):
            server.starttls(context=ssl_module.create_default_context())
        server.login(config['smtp_user'], config['smtp_password'])
        server.sendmail(config['from_email'], config['to_emails'], msg.as_string())
        server.quit()
        
        logger.info(f"Error notification sent for {domain}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send error notification for {domain}: {e}")
        return False