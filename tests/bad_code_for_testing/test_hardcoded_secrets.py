"""
Test file with hardcoded secrets that should be detected
by the hardcoded secrets checker.
"""

import os
import requests

# Hardcoded API keys
API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
OPENAI_API_KEY = "sk-or-v1-abcdef1234567890abcdef1234567890abcdef"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"

# Hardcoded passwords
DATABASE_PASSWORD = "myComplexDbPass2024!"
ADMIN_PASSWORD = "admin123"
USER_PASSWORD = "userSecret456"

# Hardcoded tokens
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
JWT_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2ODQ4NjQwMDAsImV4cCI6MTcxNjQwMDAwMCwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSJ9.K3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q3Q"

# AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database connection strings
DATABASE_URL = "postgresql://user:super_secret_pass@localhost:5432/mydb"
MYSQL_CONNECTION = "mysql://admin:password123@db.example.com:3306/app_db"

# OAuth secrets
CLIENT_ID = "123456789-abcdef123456789abcdef.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-abcdef123456789abcdef123456789"

# Stripe keys
STRIPE_PUBLISHABLE_KEY = "pk_test_1234567890abcdef1234567890abcdef"
STRIPE_SECRET_KEY = "sk_test_1234567890abcdef1234567890abcdef"

# Generic secrets
SECRET_KEY = "django-insecure-abcdef1234567890abcdef1234567890abcdef"
ENCRYPTION_KEY = "1234567890abcdef1234567890abcdef12345678"

class APIClient:
    """API client with hardcoded secrets."""

    def __init__(self):
        self.api_key = "xoxp-1234567890-1234567890-abcdef1234567890abcdef"
        self.slack_token = "xoxb-your-slack-bot-token-here-1234567890"

    def make_request(self, endpoint):
        """Make API request with hardcoded auth."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-API-Key": "apikey_1234567890abcdef1234567890abcdef"
        }
        # This would be a security issue
        response = requests.get(f"https://api.example.com{endpoint}", headers=headers)
        return response.json()

def connect_to_database():
    """Connect to database with hardcoded credentials."""
    # Hardcoded database credentials - very bad practice!
    db_config = {
        "host": "localhost",
        "user": "admin",
        "password": "root123",
        "database": "sensitive_data"
    }

    # This is just an example - don't actually connect
    print(f"Connecting to {db_config['database']} as {db_config['user']}")
    return db_config

def authenticate_user():
    """Authenticate with hardcoded service account."""
    service_account = {
        "type": "service_account",
        "project_id": "my-project-123456",
        "private_key_id": "abcdef1234567890abcdef1234567890abcdef",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----\n",
        "client_email": "service-account@my-project.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
    }

    return service_account

# Environment variables that should be used instead
def get_config():
    """Get configuration - this shows the correct way."""
    return {
        "api_key": os.getenv("API_KEY"),
        "database_url": os.getenv("DATABASE_URL"),
        "secret_key": os.getenv("SECRET_KEY")
    }

# More hardcoded secrets in different formats
config = {
    "redis": {
        "host": "localhost",
        "password": "redis_password_123!"
    },
    "email": {
        "smtp_server": "smtp.gmail.com",
        "username": "noreply@example.com",
        "password": "email_password_123"
    }
}

# SSH private key (simulated)
SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDabcdefghijklmnop1234567890abcdefghijklmnopAAA
-----END OPENSSH PRIVATE KEY-----"""

# Webhook secrets
GITHUB_WEBHOOK_SECRET = "webhook_secret_abcdef1234567890"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
