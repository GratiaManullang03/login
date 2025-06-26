"""
Email service untuk SecureAuth API.
Menangani pengiriman email untuk berbagai keperluan.
"""

from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional, Dict, Any
import asyncio
from functools import partial
import jinja2
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import ServiceUnavailableException


class EmailService:
    """
    Service class untuk email operations.
    Menangani template rendering dan email sending.
    """
    
    def __init__(self):
        """Initialize email service dengan template engine."""
        # Setup Jinja2 untuk email templates
        template_dir = Path(__file__).parent.parent / "templates" / "emails"
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=True
        )
        
        # Base context untuk semua email
        self.base_context = {
            "app_name": settings.APP_NAME,
            "support_email": settings.EMAIL_FROM_ADDRESS,
            "year": datetime.now().year
        }
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        Send email menggunakan SMTP.
        
        Args:
            to_email: Recipient email
            subject: Email subject
            html_body: HTML content
            text_body: Plain text content (optional)
            cc: CC recipients
            bcc: BCC recipients
            attachments: List of attachments
            
        Returns:
            True jika email berhasil dikirim
            
        Raises:
            ServiceUnavailableException: Jika SMTP service tidak tersedia
        """
        # Run in thread pool karena smtplib blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            partial(
                self._send_email_sync,
                to_email=to_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                cc=cc,
                bcc=bcc,
                attachments=attachments
            )
        )
    
    def _send_email_sync(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        Synchronous email sending implementation.
        
        Args:
            Same as send_email
            
        Returns:
            True jika berhasil
        """
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM_ADDRESS}>"
            msg["To"] = to_email
            
            if cc:
                msg["Cc"] = ", ".join(cc)
            
            # Add text part
            if text_body:
                text_part = MIMEText(text_body, "plain", "utf-8")
                msg.attach(text_part)
            
            # Add HTML part
            html_part = MIMEText(html_body, "html", "utf-8")
            msg.attach(html_part)
            
            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    # Implementation untuk attachments
                    pass
            
            # Recipients list
            recipients = [to_email]
            if cc:
                recipients.extend(cc)
            if bcc:
                recipients.extend(bcc)
            
            # Connect to SMTP server
            if settings.SMTP_SSL:
                server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)
            else:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
                if settings.SMTP_TLS:
                    server.starttls()
            
            # Login if credentials provided
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            
            # Send email
            server.send_message(msg, to_addrs=recipients)
            server.quit()
            
            return True
            
        except smtplib.SMTPException as e:
            # Log error
            print(f"SMTP error sending email: {str(e)}")
            raise ServiceUnavailableException("Email service temporarily unavailable")
        except Exception as e:
            # Log error
            print(f"Error sending email: {str(e)}")
            return False
    
    async def send_verification_email(
        self,
        email: str,
        username: str,
        verification_token: str
    ) -> bool:
        """
        Send email verification email.
        
        Args:
            email: User email
            username: Username
            verification_token: Verification token
            
        Returns:
            True jika berhasil
        """
        # Build verification URL
        verification_url = f"{settings.FRONTEND_URL}verify-email?token={verification_token}"
        
        # Render template
        context = {
            **self.base_context,
            "username": username,
            "verification_url": verification_url,
            "expires_hours": settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
        }
        
        try:
            html_template = self.template_env.get_template("verification.html")
            text_template = self.template_env.get_template("verification.txt")
            
            html_body = html_template.render(**context)
            text_body = text_template.render(**context)
        except jinja2.TemplateNotFound:
            # Fallback jika template tidak ada
            html_body = f"""
            <h2>Welcome to {settings.APP_NAME}, {username}!</h2>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href="{verification_url}">Verify Email</a></p>
            <p>This link will expire in {settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS} hours.</p>
            <p>If you didn't create an account, please ignore this email.</p>
            """
            text_body = f"""
            Welcome to {settings.APP_NAME}, {username}!
            
            Please verify your email address by visiting:
            {verification_url}
            
            This link will expire in {settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS} hours.
            
            If you didn't create an account, please ignore this email.
            """
        
        return await self.send_email(
            to_email=email,
            subject=f"Verify your {settings.APP_NAME} account",
            html_body=html_body,
            text_body=text_body
        )
    
    async def send_password_reset_email(
        self,
        email: str,
        username: str,
        reset_token: str
    ) -> bool:
        """
        Send password reset email.
        
        Args:
            email: User email
            username: Username
            reset_token: Password reset token
            
        Returns:
            True jika berhasil
        """
        # Build reset URL
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        
        # Render template
        context = {
            **self.base_context,
            "username": username,
            "reset_url": reset_url,
            "expires_hours": settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS
        }
        
        try:
            html_template = self.template_env.get_template("password_reset.html")
            text_template = self.template_env.get_template("password_reset.txt")
            
            html_body = html_template.render(**context)
            text_body = text_template.render(**context)
        except jinja2.TemplateNotFound:
            # Fallback
            html_body = f"""
            <h2>Password Reset Request</h2>
            <p>Hi {username},</p>
            <p>We received a request to reset your password. Click the link below to reset it:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in {settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS} hours.</p>
            <p>If you didn't request this, please ignore this email. Your password won't be changed.</p>
            """
            text_body = f"""
            Password Reset Request
            
            Hi {username},
            
            We received a request to reset your password. Visit the link below to reset it:
            {reset_url}
            
            This link will expire in {settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS} hours.
            
            If you didn't request this, please ignore this email. Your password won't be changed.
            """
        
        return await self.send_email(
            to_email=email,
            subject=f"Reset your {settings.APP_NAME} password",
            html_body=html_body,
            text_body=text_body
        )
    
    async def send_account_locked_email(
        self,
        email: str,
        username: str,
        locked_until: datetime,
        reason: str
    ) -> bool:
        """
        Send account locked notification.
        
        Args:
            email: User email
            username: Username
            locked_until: Lock expiration
            reason: Lock reason
            
        Returns:
            True jika berhasil
        """
        context = {
            **self.base_context,
            "username": username,
            "locked_until": locked_until.strftime("%Y-%m-%d %H:%M UTC"),
            "reason": reason
        }
        
        html_body = f"""
        <h2>Account Security Alert</h2>
        <p>Hi {username},</p>
        <p>Your {settings.APP_NAME} account has been temporarily locked due to: {reason}</p>
        <p>Your account will be automatically unlocked at: <strong>{locked_until.strftime("%Y-%m-%d %H:%M UTC")}</strong></p>
        <p>If you believe this is a mistake, please contact our support team.</p>
        """
        
        text_body = f"""
        Account Security Alert
        
        Hi {username},
        
        Your {settings.APP_NAME} account has been temporarily locked due to: {reason}
        
        Your account will be automatically unlocked at: {locked_until.strftime("%Y-%m-%d %H:%M UTC")}
        
        If you believe this is a mistake, please contact our support team.
        """
        
        return await self.send_email(
            to_email=email,
            subject=f"{settings.APP_NAME} Account Security Alert",
            html_body=html_body,
            text_body=text_body
        )
    
    async def send_2fa_enabled_email(
        self,
        email: str,
        username: str,
        backup_codes: List[str]
    ) -> bool:
        """
        Send 2FA enabled confirmation dengan backup codes.
        
        Args:
            email: User email
            username: Username
            backup_codes: List of backup codes
            
        Returns:
            True jika berhasil
        """
        # Format backup codes
        codes_html = "<ul>" + "".join(f"<li><code>{code}</code></li>" for code in backup_codes) + "</ul>"
        codes_text = "\n".join(f"- {code}" for code in backup_codes)
        
        html_body = f"""
        <h2>Two-Factor Authentication Enabled</h2>
        <p>Hi {username},</p>
        <p>You have successfully enabled two-factor authentication on your {settings.APP_NAME} account.</p>
        <p><strong>Your backup codes:</strong></p>
        {codes_html}
        <p><strong>Important:</strong> Save these codes in a secure place. Each code can only be used once.</p>
        <p>You can use these codes to access your account if you lose access to your authenticator device.</p>
        """
        
        text_body = f"""
        Two-Factor Authentication Enabled
        
        Hi {username},
        
        You have successfully enabled two-factor authentication on your {settings.APP_NAME} account.
        
        Your backup codes:
        {codes_text}
        
        Important: Save these codes in a secure place. Each code can only be used once.
        You can use these codes to access your account if you lose access to your authenticator device.
        """
        
        return await self.send_email(
            to_email=email,
            subject=f"{settings.APP_NAME} - Two-Factor Authentication Enabled",
            html_body=html_body,
            text_body=text_body
        )
    
    async def send_new_device_alert_email(
        self,
        email: str,
        username: str,
        device_info: Dict[str, Any],
        ip_address: str,
        timestamp: datetime
    ) -> bool:
        """
        Send alert untuk new device login.
        
        Args:
            email: User email
            username: Username
            device_info: Device information
            ip_address: Login IP
            timestamp: Login timestamp
            
        Returns:
            True jika berhasil
        """
        device_name = device_info.get("device_name", "Unknown Device")
        platform = device_info.get("platform", "Unknown")
        browser = device_info.get("browser", "Unknown")
        
        html_body = f"""
        <h2>New Device Login Alert</h2>
        <p>Hi {username},</p>
        <p>Your {settings.APP_NAME} account was accessed from a new device:</p>
        <ul>
            <li><strong>Device:</strong> {device_name}</li>
            <li><strong>Platform:</strong> {platform}</li>
            <li><strong>Browser:</strong> {browser}</li>
            <li><strong>IP Address:</strong> {ip_address}</li>
            <li><strong>Time:</strong> {timestamp.strftime("%Y-%m-%d %H:%M UTC")}</li>
        </ul>
        <p>If this was you, you can safely ignore this email.</p>
        <p>If this wasn't you, please secure your account immediately by changing your password.</p>
        """
        
        text_body = f"""
        New Device Login Alert
        
        Hi {username},
        
        Your {settings.APP_NAME} account was accessed from a new device:
        
        - Device: {device_name}
        - Platform: {platform}
        - Browser: {browser}
        - IP Address: {ip_address}
        - Time: {timestamp.strftime("%Y-%m-%d %H:%M UTC")}
        
        If this was you, you can safely ignore this email.
        If this wasn't you, please secure your account immediately by changing your password.
        """
        
        return await self.send_email(
            to_email=email,
            subject=f"{settings.APP_NAME} - New Device Login",
            html_body=html_body,
            text_body=text_body
        )