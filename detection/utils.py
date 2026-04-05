import re

def detect_phishing(url):
    # Add common phishing patterns
    phishing_patterns = [
        r'secure-\w+',
        r'login-\w+',
        r'\.ru/',          # URLs ending with ".ru"
        r'free-\w+',       # Free services
        r'-paypal',        # Fake PayPal phishing
    ]
    for pattern in phishing_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False


# utils.py
import re
import os

phishing_keywords = ["urgent", "verify", "click here", "security alert"]
suspicious_domains = ["secure-paypal.com", "fake-login.com", "account-verify.com"]
suspicious_extensions = [".exe", ".scr", ".bat", ".vbs", ".js"]

def detect_phishing_links(email_body):
    phishing_alerts = []
    links = re.findall(r"https?://[^\s]+", email_body)
    for link in links:
        for domain in suspicious_domains:
            if domain in link:
                phishing_alerts.append(f"⚠️ Suspicious link detected: {link}")
    return phishing_alerts

def validate_sender_email(sender_email):
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", sender_email):
        return "⚠️ Invalid email format."
    if any(domain in sender_email for domain in suspicious_domains):
        return f"⚠️ Suspicious sender email: {sender_email}"
    return None

def check_attachments(email_attachments):
    attachment_alerts = []
    for file in email_attachments:
        filename = file.name.lower()
        file_extension = os.path.splitext(filename)[1]  
        if file_extension in suspicious_extensions:
            attachment_alerts.append(f"⚠️ Dangerous file type: {filename}")
    return attachment_alerts

def detect_fraudulent_email(email_body, sender_email, email_attachments):
    alerts = []
    alerts += detect_phishing_links(email_body)
    sender_alert = validate_sender_email(sender_email)
    if sender_alert:
        alerts.append(sender_alert)
    alerts += check_attachments(email_attachments)
    return f"⚠️ Suspicious email detected: {', '.join(alerts)}" if alerts else "✅ This email looks safe."
