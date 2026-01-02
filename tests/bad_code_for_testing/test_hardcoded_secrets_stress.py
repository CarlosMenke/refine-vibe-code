"""
Comprehensive stress test file for hardcoded secrets checker.
Tests various edge cases, false positives, complex scenarios, and boundary conditions.
"""

import os
import json
import yaml
import configparser
from typing import Dict, List

# ==========================================
# BASIC SECRETS (SHOULD BE DETECTED)
# ==========================================

# Standard API keys
STRIPE_PUBLIC_KEY = "pk_test_51HXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
STRIPE_SECRET_KEY = "sk_test_51HXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Various API key formats
OPENAI_KEY = "sk-or-v1-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
ANTHROPIC_KEY = "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
GOOGLE_API_KEY = "AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Database credentials
DB_PASSWORD = "super_secure_db_password_2024!"
REDIS_PASSWORD = "redis_password_complex_123456"
MONGO_PASSWORD = "mongodb_password_secure_987654"

# JWT secrets
JWT_SECRET = "your-256-bit-secret-here-make-it-long-and-secure-1234567890abcdef"
SESSION_SECRET = "django-insecure-abcdef1234567890abcdef1234567890abcdef"

# OAuth credentials
GITHUB_CLIENT_ID = "Iv1.XXXXXXXXXXXXXXXXXXXX"
GITHUB_CLIENT_SECRET = "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ==========================================
# EDGE CASES (SHOULD BE DETECTED)
# ==========================================

# Secrets in different quote types
SINGLE_QUOTE_SECRET = 'sk-1234567890abcdef1234567890abcdef12345678'
DOUBLE_QUOTE_SECRET = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Secrets with special characters
SPECIAL_CHARS_SECRET = "sk_test_1234567890abcdef!@#$%^&*()_+-=[]{}|;:,.<>?"

# Very long secrets
VERY_LONG_SECRET = "sk-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Secrets in different cases
UPPERCASE_SECRET = "SK-1234567890ABCDEF1234567890ABCDEF12345678"
MIXED_CASE_SECRET = "Sk-TeSt1234567890AbCdEf1234567890AbCdEf12345678"

# ==========================================
# COMPLEX OBJECTS WITH SECRETS
# ==========================================

# Dictionary with secrets
CONFIG_DICT = {
    "database": {
        "host": "localhost",
        "password": "db_password_secret_123!",
        "ssl_cert": "-----BEGIN CERTIFICATE-----\nMIICiTCCAg+gAwIBAgIJAJ8l2Z2Z3Z3ZMAOGA1UEBhMCVVMxCzAJBgNVBAgTAkNB\n-----END CERTIFICATE-----"
    },
    "api_keys": {
        "openai": "sk-or-v1-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "stripe": "sk_test_51HXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "github": "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    },
    "auth": {
        "jwt_secret": "your-256-bit-secret-here-make-it-long-and-secure-1234567890abcdef",
        "session_key": "django-insecure-abcdef1234567890abcdef1234567890abcdef"
    }
}

# List with secrets
SECRETS_LIST = [
    "sk-1234567890abcdef1234567890abcdef12345678",
    "password: super_secret_123!",
    "token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "api_key: pk_test_51HXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
]

# ==========================================
# FALSE POSITIVES (SHOULD NOT BE DETECTED)
# ==========================================

# Short strings that look like secrets but aren't
SHORT_STRING = "abc123"
TOO_SHORT = "sk-12345"

# Common words that might match patterns
NORMAL_WORDS = {
    "password": "not_a_real_password",
    "token": "not_a_real_token",
    "secret": "not_a_real_secret",
    "key": "not_a_real_key"
}

# Placeholder values
PLACEHOLDER_SECRETS = {
    "api_key": "your_api_key_here",
    "password": "your_password_here",
    "secret": "your_secret_here",
    "token": "your_token_here"
}

# Test data that looks like secrets
TEST_DATA = {
    "fake_api_key": "pk_test_fake_key_1234567890abcdef",
    "test_password": "test_password_123",
    "mock_secret": "mock_secret_for_testing_1234567890abcdef"
}

# ==========================================
# SECRETS IN CODE CONTEXTS
# ==========================================

class APIClient:
    """API client with hardcoded secrets."""

    def __init__(self):
        # Instance variables with secrets
        self.api_key = "sk-1234567890abcdef1234567890abcdef12345678"
        self.secret_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        self.db_password = "complex_database_password_2024!"

    def authenticate(self):
        """Authenticate with hardcoded credentials."""
        headers = {
            "Authorization": f"Bearer {self.secret_token}",
            "X-API-Key": self.api_key
        }
        return headers

def connect_to_database():
    """Database connection with hardcoded credentials."""
    # This is a security issue
    connection_params = {
        "host": "localhost",
        "user": "admin",
        "password": "hardcoded_db_password_123!",  # Should be detected
        "database": "sensitive_data"
    }
    return connection_params

# ==========================================
# ENVIRONMENT VARIABLES (SHOULD NOT BE DETECTED)
# ==========================================

def get_config_from_env():
    """Proper way to handle secrets via environment variables."""
    return {
        "api_key": os.getenv("API_KEY"),
        "database_url": os.getenv("DATABASE_URL"),
        "secret_key": os.getenv("SECRET_KEY"),
        "jwt_secret": os.getenv("JWT_SECRET")
    }

# ==========================================
# COMPLEX STRING OPERATIONS
# ==========================================

def build_connection_string():
    """Building connection strings with secrets."""
    # These should be detected as hardcoded secrets
    host = "localhost"
    user = "admin"
    password = "hardcoded_password_123!"  # Should be detected
    db = "mydb"

    # String concatenation
    conn_str = f"postgresql://{user}:{password}@{host}/{db}"

    # String formatting
    conn_str2 = "mysql://{}:{}@{}/{}".format(user, password, host, db)

    # f-string with secret
    conn_str3 = f"mongodb://{user}:{password}@{host}/{db}"

    return conn_str, conn_str2, conn_str3

# ==========================================
# JSON AND CONFIG FILES CONTENT
# ==========================================

# JSON-like string with secrets (should be detected)
CONFIG_JSON_STR = '''
{
  "database": {
    "host": "localhost",
    "password": "json_embedded_password_123!",
    "ssl": true
  },
  "api": {
    "key": "sk-1234567890abcdef1234567890abcdef12345678",
    "endpoint": "https://api.example.com"
  }
}
'''

# YAML-like content
CONFIG_YAML_STR = """
database:
  host: localhost
  password: yaml_embedded_password_123!
  port: 5432

api_keys:
  openai: sk-or-v1-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  stripe: sk_test_51HXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
"""

# INI-style config
CONFIG_INI_STR = """
[database]
host=localhost
password=ini_embedded_password_123!
port=3306

[api]
key=sk-1234567890abcdef1234567890abcdef12345678
secret=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
"""

# ==========================================
# ENCODING AND OBFUSCATION ATTEMPTS
# ==========================================

import base64

# Base64 encoded secrets (should be detected if decoded)
ENCODED_SECRET = "c2stMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3OA=="  # base64 of sk-1234567890abcdef1234567890abcdef12345678

# Hex encoded
HEX_SECRET = "736b2d3132333435363738393061626364656631323334353637383930616263646566313233343536373839306162636465663132333435363738"

# Rot13 (simple obfuscation)
ROT13_SECRET = "fx-1234567890nopqrs1234567890nopqrs12345678"

# ==========================================
# SECRETS IN COMMENTS AND DOCSTRINGS
# ==========================================

def function_with_secret_in_comment():
    """
    This function connects to database.

    Database password: hardcoded_password_in_docstring_123!
    API Key: sk-1234567890abcdef1234567890abcdef12345678
    """
    # API key: sk-1234567890abcdef1234567890abcdef12345678
    # Password: secret_password_123!
    return "connected"

# ==========================================
# MULTILINE SECRETS
# ==========================================

# Multiline string with secrets
MULTILINE_CONFIG = """
Host: localhost
User: admin
Password: multiline_secret_password_123!
API_Key: sk-1234567890abcdef1234567890abcdef12345678
SSL_Cert: -----BEGIN CERTIFICATE-----
MIICiTCCAg+gAwIBAgIJAJ8l2Z2Z3Z3ZMAOGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
...
-----END CERTIFICATE-----
"""

# ==========================================
# SECRETS IN DIFFERENT FORMATS
# ==========================================

# URL-encoded secrets
URL_ENCODED_SECRET = "password=hardcoded%2Bpassword%2B123%21"

# Query string format
QUERY_STRING = "api_key=sk-1234567890abcdef1234567890abcdef12345678&secret=Bearer+eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# ==========================================
# BOUNDARY CASES
# ==========================================

# Exactly minimum length secrets
MIN_LENGTH_SECRET = "sk-1234567890abcd"  # 20 chars after sk-
MIN_PASSWORD = "password8"  # 8 chars minimum

# Maximum length secrets
MAX_LENGTH_SECRET = "sk-" + "a" * 1000  # Very long secret

# Secrets with numbers only
NUMERIC_SECRET = "1234567890123456789012345678901234567890"

# Secrets with special chars only
SPECIAL_SECRET = "!@#$%^&*()_+-=[]{}|;:,.<>?1234567890abcdef"

# ==========================================
# CONTEXTUAL FALSE POSITIVES
# ==========================================

# Code examples in documentation
EXAMPLE_CODE = '''
def connect_to_db():
    # Example: password = "your_password_here"
    # Real usage: password = os.getenv("DB_PASSWORD")
    pass
'''

# Test constants
TEST_CONSTANTS = {
    "TEST_API_KEY": "test_key_1234567890abcdef",
    "MOCK_PASSWORD": "mock_password_123",
    "FAKE_SECRET": "fake_secret_for_unit_tests_1234567890abcdef"
}

# ==========================================
# SECRETS IN EXCEPTIONS AND LOGGING
# ==========================================

def log_sensitive_data():
    """Logging sensitive information."""
    password = "logged_password_123!"
    api_key = "sk-1234567890abcdef1234567890abcdef12345678"

    # This should be flagged - logging secrets
    print(f"Debug: password={password}, api_key={api_key}")

    try:
        # Some operation
        pass
    except Exception as e:
        # Logging sensitive data in exceptions
        raise Exception(f"Failed with password: {password}") from e

# ==========================================
# SECRETS IN TEST METHODS
# ==========================================

class TestSecrets:
    """Test class with secrets."""

    def test_api_call(self):
        """Test method with hardcoded test secrets."""
        # These might be acceptable in tests but should still be flagged
        test_api_key = "sk-test-1234567890abcdef1234567890abcdef12345678"
        test_password = "test_password_123!"

        # Test logic here
        assert test_api_key.startswith("sk-")
        assert len(test_password) > 8

# ==========================================
# SECRETS IN CONFIG CLASSES
# ==========================================

class DatabaseConfig:
    """Database configuration with secrets."""

    HOST = "localhost"
    USER = "admin"
    PASSWORD = "class_level_password_123!"  # Should be detected
    DATABASE = "mydb"

    @classmethod
    def get_connection_string(cls):
        return f"postgresql://{cls.USER}:{cls.PASSWORD}@{cls.HOST}/{cls.DATABASE}"

# ==========================================
# SECRETS IN LAMBDA FUNCTIONS
# ==========================================

# Lambda with hardcoded secret
get_auth_header = lambda api_key="sk-1234567890abcdef1234567890abcdef12345678": {
    "Authorization": f"Bearer {api_key}"
}

# ==========================================
# SECRETS IN COMPREHENSIONS
# ==========================================

# List comprehension with secrets
SECRET_LIST = [f"secret_{i}_value" for i in range(10)]
API_KEYS = ["sk-" + str(i).zfill(32) for i in range(5)]

# ==========================================
# SECRETS IN GENERATOR EXPRESSIONS
# ==========================================

def generate_secrets():
    """Generator that yields secrets."""
    secrets = [
        "sk-1234567890abcdef1234567890abcdef12345678",
        "password: generator_secret_123!",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ]
    for secret in secrets:
        yield secret

# ==========================================
# SECRETS IN NESTED STRUCTURES
# ==========================================

NESTED_CONFIG = {
    "production": {
        "database": {
            "credentials": {
                "username": "prod_user",
                "password": "nested_secret_password_123!"
            }
        },
        "api": {
            "keys": [
                "sk-prod-1234567890abcdef1234567890abcdef12345678",
                "pk-prod-1234567890abcdef1234567890abcdef12345678"
            ]
        }
    },
    "staging": {
        "database": {
            "password": "staging_secret_123!"
        }
    }
}

# ==========================================
# SECRETS IN STRING TEMPLATES
# ==========================================

from string import Template

# String template with secrets
EMAIL_TEMPLATE = Template("""
Dear user,

Your API key is: $api_key
Your password is: $password

Best regards,
Admin
""")

def send_welcome_email():
    """Send welcome email with secrets."""
    # This should be flagged
    template_vars = {
        "api_key": "sk-1234567890abcdef1234567890abcdef12345678",
        "password": "welcome_password_123!"
    }

    email_body = EMAIL_TEMPLATE.substitute(template_vars)
    return email_body

# ==========================================
# SECRETS IN REGEX PATTERNS
# ==========================================

import re

# Regex patterns that contain secrets
SECRET_PATTERN = re.compile(r'sk-1234567890abcdef1234567890abcdef12345678')
PASSWORD_PATTERN = re.compile(r'password:\s*(hardcoded_regex_password_123!)')

def validate_with_secret_pattern(input_string):
    """Validate input using regex with embedded secrets."""
    if SECRET_PATTERN.search(input_string):
        return True
    if PASSWORD_PATTERN.search(input_string):
        return True
    return False

# ==========================================
# SECRETS IN DOCSTRING EXAMPLES
# ==========================================

def authenticate_user(username, password):
    """
    Authenticate a user with the given credentials.

    Args:
        username (str): The user's username
        password (str): The user's password

    Returns:
        bool: True if authentication successful

    Example:
        >>> # This is just an example - don't use real credentials
        >>> authenticate_user("admin", "real_password_123!")
        True

        >>> authenticate_user("user", "sk-1234567890abcdef1234567890abcdef12345678")
        False
    """
    # Real implementation would check against database
    return username == "admin" and password == "secret_admin_password_123!"

# ==========================================
# SECRETS IN TYPE HINTS AND ANNOTATIONS
# ==========================================

from typing import Literal

# Type hints with secret values
SecretType = Literal["sk-1234567890abcdef1234567890abcdef12345678", "password_123!"]

def process_secret(secret: SecretType) -> bool:
    """Process a secret value."""
    return secret in ["sk-1234567890abcdef1234567890abcdef12345678", "password_123!"]

# ==========================================
# SECRETS IN ASSERT STATEMENTS
# ==========================================

def test_secret_handling():
    """Test function with secrets in assertions."""
    api_key = "sk-1234567890abcdef1234567890abcdef12345678"
    password = "assert_password_123!"

    # Assertions with secrets (should be flagged)
    assert api_key.startswith("sk-")
    assert len(password) >= 8
    assert password == "assert_password_123!"

# ==========================================
# SECRETS IN EXCEPTION MESSAGES
# ==========================================

class AuthenticationError(Exception):
    """Authentication error with embedded secrets."""

    def __init__(self, message="Authentication failed"):
        self.default_api_key = "sk-1234567890abcdef1234567890abcdef12345678"
        self.default_password = "exception_password_123!"
        super().__init__(f"{message} - check api_key: {self.default_api_key}")

# ==========================================
# SECRETS IN CLASS DOCSTRINGS
# ==========================================

class SecretManager:
    """
    Manages application secrets and credentials.

    This class handles:
    - API keys: sk-1234567890abcdef1234567890abcdef12345678
    - Passwords: class_docstring_password_123!
    - Tokens: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

    Note: Never hardcode real secrets in production code.
    """

    def __init__(self):
        self.stored_secrets = {
            "api_key": "sk-1234567890abcdef1234567890abcdef12345678",
            "password": "class_docstring_password_123!"
        }

# ==========================================
# SECRETS IN MODULE LEVEL CODE
# ==========================================

# Module-level secret initialization
module_api_key = "sk-1234567890abcdef1234567890abcdef12345678"
module_password = "module_level_password_123!"

# Conditional secret loading (still hardcoded)
if os.getenv("ENV") == "development":
    DEV_SECRET = "dev_secret_1234567890abcdef"
else:
    PROD_SECRET = "prod_secret_1234567890abcdef"

# ==========================================
# SECRETS IN DECORATORS
# ==========================================

def require_auth(api_key="sk-1234567890abcdef1234567890abcdef12345678"):
    """Decorator that requires authentication."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if api_key != "sk-1234567890abcdef1234567890abcdef12345678":
                raise AuthenticationError("Invalid API key")
            return func(*args, **kwargs)
        return wrapper
    return decorator

@require_auth(api_key="sk-1234567890abcdef1234567890abcdef12345678")
def protected_function():
    """Function protected by hardcoded API key."""
    return "protected data"

# ==========================================
# SECRETS IN METACLASSES
# ==========================================

class SecretMeta(type):
    """Metaclass that handles secrets."""

    def __new__(cls, name, bases, namespace, **kwargs):
        # Add default secrets to class
        namespace['DEFAULT_API_KEY'] = "sk-1234567890abcdef1234567890abcdef12345678"
        namespace['DEFAULT_PASSWORD'] = "meta_password_123!"
        return super().__new__(cls, name, bases, namespace)

class SecretClass(metaclass=SecretMeta):
    """Class created with metaclass that adds secrets."""

    def get_secrets(self):
        return {
            "api_key": self.DEFAULT_API_KEY,
            "password": self.DEFAULT_PASSWORD
        }

# ==========================================
# SECRETS IN CONTEXT MANAGERS
# ==========================================

from contextlib import contextmanager

@contextmanager
def database_connection(password="context_manager_password_123!"):
    """Context manager for database connections."""
    # This should be flagged
    print(f"Connecting with password: {password}")
    try:
        yield "connection_object"
    finally:
        print("Connection closed")

def use_database():
    """Use database with context manager."""
    with database_connection(password="context_manager_password_123!") as conn:
        return f"Using {conn}"

# ==========================================
# SECRETS IN ASYNC FUNCTIONS
# ==========================================

import asyncio

async def async_api_call(api_key="sk-1234567890abcdef1234567890abcdef12345678"):
    """Async function with hardcoded API key."""
    # Simulate API call
    await asyncio.sleep(0.1)
    return f"Called API with key: {api_key}"

async def async_authenticate(password="async_password_123!"):
    """Async authentication function."""
    await asyncio.sleep(0.1)
    return password == "async_password_123!"

# ==========================================
# SECRETS IN GENERICS AND TYPE VARIABLES
# ==========================================

from typing import TypeVar, Generic

T = TypeVar('T')

class SecretContainer(Generic[T]):
    """Generic container for secrets."""

    def __init__(self, secret: T = "sk-1234567890abcdef1234567890abcdef12345678"):
        self.secret = secret

    def get_secret(self) -> T:
        return self.secret

# ==========================================
# SECRETS IN ENUMS
# ==========================================

from enum import Enum

class SecretEnum(Enum):
    """Enum containing secrets."""

    API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
    PASSWORD = "enum_password_123!"
    TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

def use_enum_secret(secret_type: SecretEnum):
    """Use secret from enum."""
    return f"Using {secret_type.name}: {secret_type.value}"

# ==========================================
# SECRETS IN DATA CLASSES
# ==========================================

from dataclasses import dataclass

@dataclass
class Credentials:
    """Data class for credentials."""

    username: str = "admin"
    password: str = "dataclass_password_123!"
    api_key: str = "sk-1234567890abcdef1234567890abcdef12345678"

def create_credentials():
    """Create credentials instance."""
    return Credentials()

# ==========================================
# SECRETS IN NAMED TUPLES
# ==========================================

from collections import namedtuple

SecretTuple = namedtuple('SecretTuple', ['api_key', 'password', 'token'])

DEFAULT_SECRETS = SecretTuple(
    api_key="sk-1234567890abcdef1234567890abcdef12345678",
    password="namedtuple_password_123!",
    token="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
)

def get_default_secrets():
    """Get default secrets from named tuple."""
    return DEFAULT_SECRETS

# ==========================================
# SECRETS IN SLOTS CLASSES
# ==========================================

class SlottedSecrets:
    """Class with __slots__ containing secrets."""

    __slots__ = ['api_key', 'password']

    def __init__(self):
        self.api_key = "sk-1234567890abcdef1234567890abcdef12345678"
        self.password = "slotted_password_123!"

# ==========================================
# SECRETS IN PROPERTIES
# ==========================================

class PropertySecrets:
    """Class with properties that return secrets."""

    @property
    def api_key(self):
        """Get API key."""
        return "sk-1234567890abcdef1234567890abcdef12345678"

    @property
    def password(self):
        """Get password."""
        return "property_password_123!"

# ==========================================
# SECRETS IN DESCRIPTORS
# ==========================================

class SecretDescriptor:
    """Descriptor that stores secrets."""

    def __init__(self, secret_value="sk-1234567890abcdef1234567890abcdef12345678"):
        self.secret_value = secret_value

    def __get__(self, instance, owner):
        return self.secret_value

    def __set__(self, instance, value):
        self.secret_value = value

class DescriptorSecrets:
    """Class using secret descriptors."""

    api_key = SecretDescriptor("sk-1234567890abcdef1234567890abcdef12345678")
    password = SecretDescriptor("descriptor_password_123!")

# ==========================================
# SECRETS IN __ALL__ LISTS
# ==========================================

__all__ = [
    "API_KEY_CONSTANT",
    "PASSWORD_CONSTANT"
]

API_KEY_CONSTANT = "sk-1234567890abcdef1234567890abcdef12345678"
PASSWORD_CONSTANT = "all_list_password_123!"

# ==========================================
# SECRETS IN IF NAME == MAIN
# ==========================================

if __name__ == "__main__":
    # Secrets in main block
    test_api_key = "sk-1234567890abcdef1234567890abcdef12345678"
    test_password = "main_block_password_123!"

    print(f"Testing with key: {test_api_key}")
    print(f"Testing with password: {test_password}")

