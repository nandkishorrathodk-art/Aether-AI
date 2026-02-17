"""
Email & Business Automation
Intelligent email responses, scheduling, and business workflows
"""
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import json


class EmailAutomation:
    """
    Intelligent email automation system
    
    Features:
    - Auto-respond to emails
    - Smart email categorization
    - Schedule email sending
    - Email templates
    - Bulk email with personalization
    """
    
    def __init__(self, smtp_server: Optional[str] = None, smtp_port: int = 587):
        """
        Initialize email automation
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP port
        """
        self.smtp_server = smtp_server or 'smtp.gmail.com'
        self.smtp_port = smtp_port
        self.credentials = None
        
        self.templates = {}
        self.scheduled_emails = []
        
        self._load_templates()
    
    def set_credentials(self, email: str, password: str):
        """
        Set email credentials
        
        Args:
            email: Email address
            password: Email password or app-specific password
        """
        self.credentials = {'email': email, 'password': password}
    
    def send_email(self, to: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> bool:
        """
        Send email
        
        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body (HTML supported)
            attachments: List of file paths to attach
            
        Returns:
            True if sent successfully
        """
        if not self.credentials:
            print("Error: Email credentials not set")
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.credentials['email']
            msg['To'] = to
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            if attachments:
                for file_path in attachments:
                    self._attach_file(msg, file_path)
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.credentials['email'], self.credentials['password'])
                server.send_message(msg)
            
            print(f"✅ Email sent to {to}")
            return True
        
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    def _attach_file(self, msg: MIMEMultipart, file_path: str):
        """Attach file to email"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            print(f"Warning: Attachment not found: {file_path}")
            return
        
        with open(file_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {file_path.name}'
        )
        
        msg.attach(part)
    
    def generate_auto_response(self, email_content: str, sentiment: str = 'neutral') -> str:
        """
        Generate intelligent auto-response
        
        Args:
            email_content: Incoming email content
            sentiment: Email sentiment (positive, negative, neutral)
            
        Returns:
            Auto-response text
        """
        if 'urgent' in email_content.lower() or 'asap' in email_content.lower():
            return self._get_urgent_response()
        
        if 'meeting' in email_content.lower() or 'schedule' in email_content.lower():
            return self._get_meeting_response()
        
        if 'invoice' in email_content.lower() or 'payment' in email_content.lower():
            return self._get_invoice_response()
        
        return self._get_generic_response(sentiment)
    
    def _get_urgent_response(self) -> str:
        """Response for urgent emails"""
        return """
Thank you for your email. I understand this is urgent and I'm prioritizing your request.

I'll get back to you within the next few hours with a detailed response.

Best regards
"""
    
    def _get_meeting_response(self) -> str:
        """Response for meeting requests"""
        return """
Thank you for reaching out regarding a meeting.

I'm available at the following times this week:
- Tuesday 2-4 PM
- Thursday 10 AM - 12 PM
- Friday 3-5 PM

Please let me know which time works best for you.

Best regards
"""
    
    def _get_invoice_response(self) -> str:
        """Response for invoice/payment emails"""
        return """
Thank you for sending the invoice.

I've received it and will process the payment within the next 2-3 business days.

You'll receive a confirmation once payment is completed.

Best regards
"""
    
    def _get_generic_response(self, sentiment: str) -> str:
        """Generic auto-response"""
        if sentiment == 'positive':
            return """
Thank you for your email! I appreciate you reaching out.

I'll review your message and respond within 24 hours.

Best regards
"""
        elif sentiment == 'negative':
            return """
Thank you for bringing this to my attention.

I take your concerns seriously and will address them promptly. 

You can expect a detailed response within 24 hours.

Best regards
"""
        else:
            return """
Thank you for your email.

I've received your message and will respond within 24-48 hours.

Best regards
"""
    
    def categorize_email(self, subject: str, body: str) -> str:
        """
        Categorize email by topic
        
        Args:
            subject: Email subject
            body: Email body
            
        Returns:
            Category name
        """
        text = f"{subject} {body}".lower()
        
        if any(word in text for word in ['invoice', 'payment', 'billing', 'receipt']):
            return 'finance'
        
        if any(word in text for word in ['meeting', 'schedule', 'calendar', 'appointment']):
            return 'scheduling'
        
        if any(word in text for word in ['urgent', 'asap', 'emergency', 'critical']):
            return 'urgent'
        
        if any(word in text for word in ['proposal', 'contract', 'agreement', 'deal']):
            return 'business'
        
        if any(word in text for word in ['support', 'help', 'issue', 'problem', 'bug']):
            return 'support'
        
        return 'general'
    
    def schedule_email(self, to: str, subject: str, body: str, send_at: datetime, attachments: Optional[List[str]] = None):
        """
        Schedule email for later sending
        
        Args:
            to: Recipient
            subject: Subject
            body: Email body
            send_at: Datetime to send
            attachments: Attachments list
        """
        self.scheduled_emails.append({
            'to': to,
            'subject': subject,
            'body': body,
            'send_at': send_at,
            'attachments': attachments,
            'sent': False
        })
        
        print(f"📅 Email scheduled for {send_at.strftime('%Y-%m-%d %H:%M')}")
    
    def process_scheduled_emails(self):
        """Send any emails that are due"""
        now = datetime.now()
        
        for email in self.scheduled_emails:
            if not email['sent'] and email['send_at'] <= now:
                success = self.send_email(
                    email['to'],
                    email['subject'],
                    email['body'],
                    email['attachments']
                )
                
                if success:
                    email['sent'] = True
                    print(f"✅ Scheduled email sent to {email['to']}")
    
    def create_template(self, name: str, subject: str, body: str):
        """
        Create email template
        
        Args:
            name: Template name
            subject: Email subject (can include variables like {name})
            body: Email body (can include variables)
        """
        self.templates[name] = {
            'subject': subject,
            'body': body
        }
    
    def _load_templates(self):
        """Load default email templates"""
        self.create_template(
            'welcome',
            'Welcome to {company_name}!',
            '''
            <html>
            <body>
                <h2>Welcome {name}!</h2>
                <p>We're excited to have you join {company_name}.</p>
                <p>Here's what you can expect:</p>
                <ul>
                    <li>24/7 customer support</li>
                    <li>Regular updates and features</li>
                    <li>Dedicated account manager</li>
                </ul>
                <p>If you have any questions, feel free to reach out!</p>
                <p>Best regards,<br>{company_name} Team</p>
            </body>
            </html>
            '''
        )
        
        self.create_template(
            'follow_up',
            'Following up: {topic}',
            '''
            <html>
            <body>
                <p>Hi {name},</p>
                <p>I wanted to follow up on {topic}.</p>
                <p>{message}</p>
                <p>Looking forward to hearing from you.</p>
                <p>Best regards,<br>{sender_name}</p>
            </body>
            </html>
            '''
        )
        
        self.create_template(
            'invoice',
            'Invoice #{invoice_number} from {company_name}',
            '''
            <html>
            <body>
                <h2>Invoice #{invoice_number}</h2>
                <p>Dear {client_name},</p>
                <p>Please find your invoice for {service_description}.</p>
                <table border="1" cellpadding="5">
                    <tr>
                        <th>Description</th>
                        <th>Amount</th>
                    </tr>
                    <tr>
                        <td>{service_description}</td>
                        <td>${amount}</td>
                    </tr>
                </table>
                <p><strong>Total: ${amount}</strong></p>
                <p>Payment due by: {due_date}</p>
                <p>Thank you for your business!</p>
                <p>Best regards,<br>{company_name}</p>
            </body>
            </html>
            '''
        )
    
    def send_from_template(self, template_name: str, to: str, variables: Dict[str, str], attachments: Optional[List[str]] = None) -> bool:
        """
        Send email using template
        
        Args:
            template_name: Name of template
            to: Recipient
            variables: Dict of variables to fill in template
            attachments: Attachments list
            
        Returns:
            True if sent successfully
        """
        if template_name not in self.templates:
            print(f"Error: Template '{template_name}' not found")
            return False
        
        template = self.templates[template_name]
        
        subject = template['subject'].format(**variables)
        body = template['body'].format(**variables)
        
        return self.send_email(to, subject, body, attachments)
    
    def bulk_send(self, recipients: List[Dict[str, str]], template_name: str, base_variables: Optional[Dict[str, str]] = None) -> int:
        """
        Send personalized emails to multiple recipients
        
        Args:
            recipients: List of dicts with 'email' and personalization variables
            template_name: Template to use
            base_variables: Base variables for all emails
            
        Returns:
            Number of emails sent successfully
        """
        base_variables = base_variables or {}
        sent_count = 0
        
        for recipient in recipients:
            variables = {**base_variables, **recipient}
            email = variables.pop('email')
            
            if self.send_from_template(template_name, email, variables):
                sent_count += 1
        
        print(f"✅ Sent {sent_count}/{len(recipients)} emails")
        return sent_count


class BusinessAutomation:
    """
    Business workflow automation
    
    Features:
    - Invoice generation
    - Report automation
    - CRM integration
    - Task scheduling
    - Data analytics
    """
    
    def __init__(self):
        """Initialize business automation"""
        self.invoices = []
        self.reports = []
        self.tasks = []
    
    def generate_invoice(self, client: str, items: List[Dict[str, Any]], invoice_number: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate invoice
        
        Args:
            client: Client name
            items: List of items with description, quantity, price
            invoice_number: Invoice number (auto-generated if None)
            
        Returns:
            Invoice dict
        """
        if not invoice_number:
            invoice_number = f"INV-{len(self.invoices) + 1:05d}"
        
        subtotal = sum(item['quantity'] * item['price'] for item in items)
        tax = subtotal * 0.1
        total = subtotal + tax
        
        invoice = {
            'invoice_number': invoice_number,
            'client': client,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'due_date': (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
            'items': items,
            'subtotal': subtotal,
            'tax': tax,
            'total': total,
            'status': 'pending'
        }
        
        self.invoices.append(invoice)
        
        return invoice
    
    def generate_monthly_report(self, month: Optional[int] = None, year: Optional[int] = None) -> Dict[str, Any]:
        """
        Generate monthly business report
        
        Args:
            month: Month (1-12), defaults to current
            year: Year, defaults to current
            
        Returns:
            Report dict
        """
        now = datetime.now()
        month = month or now.month
        year = year or now.year
        
        month_invoices = [
            inv for inv in self.invoices
            if inv['date'].startswith(f"{year}-{month:02d}")
        ]
        
        total_revenue = sum(inv['total'] for inv in month_invoices)
        paid_invoices = [inv for inv in month_invoices if inv.get('status') == 'paid']
        pending_invoices = [inv for inv in month_invoices if inv.get('status') == 'pending']
        
        report = {
            'month': f"{year}-{month:02d}",
            'total_invoices': len(month_invoices),
            'total_revenue': total_revenue,
            'paid_invoices': len(paid_invoices),
            'pending_invoices': len(pending_invoices),
            'paid_amount': sum(inv['total'] for inv in paid_invoices),
            'pending_amount': sum(inv['total'] for inv in pending_invoices),
            'average_invoice': total_revenue / len(month_invoices) if month_invoices else 0
        }
        
        self.reports.append(report)
        
        return report
    
    def schedule_task(self, task_name: str, schedule_at: datetime, details: Optional[Dict[str, Any]] = None):
        """
        Schedule business task
        
        Args:
            task_name: Task name
            schedule_at: When to execute
            details: Additional task details
        """
        task = {
            'name': task_name,
            'scheduled_at': schedule_at,
            'details': details or {},
            'status': 'pending',
            'created_at': datetime.now()
        }
        
        self.tasks.append(task)
        
        print(f"📋 Task '{task_name}' scheduled for {schedule_at.strftime('%Y-%m-%d %H:%M')}")
    
    def get_pending_tasks(self) -> List[Dict[str, Any]]:
        """Get all pending tasks"""
        return [task for task in self.tasks if task['status'] == 'pending']
    
    def mark_invoice_paid(self, invoice_number: str):
        """Mark invoice as paid"""
        for invoice in self.invoices:
            if invoice['invoice_number'] == invoice_number:
                invoice['status'] = 'paid'
                invoice['paid_date'] = datetime.now().strftime('%Y-%m-%d')
                print(f"✅ Invoice {invoice_number} marked as paid")
                return True
        
        print(f"❌ Invoice {invoice_number} not found")
        return False


email_automation = EmailAutomation()
business_automation = BusinessAutomation()


if __name__ == "__main__":
    print("Email & Business Automation Module")
    print("Set credentials with: email_automation.set_credentials('your@email.com', 'password')")
    print("Send email with: email_automation.send_email('recipient@email.com', 'Subject', 'Body')")
