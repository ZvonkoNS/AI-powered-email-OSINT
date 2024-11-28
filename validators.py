import re
import dns.resolver

def validate_email(email):
    """Validate email syntax and domain existence."""
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(regex, email):
        return False, "❌ Invalid email format!"
    domain = email.split('@')[1]
    try:
        dns.resolver.resolve(domain, 'MX')
        return True, "✅ Email validation successful!"
    except Exception as e:
        return False, f"❌ Domain validation failed: {e}"
