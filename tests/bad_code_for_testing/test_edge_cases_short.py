"""
Comprehensive stress test file for edge cases checker.
Tests various potential bugs, missing error handling, and complex scenarios.
"""

import os
import json
import requests
from typing import List, Dict, Any, Optional
import tempfile

# ==========================================
# NULL/UNDEFINED/NONE HANDLING ISSUES
# ==========================================

def process_user_data(user_data):
    """Missing null checks."""
    # No check if user_data is None
    name = user_data['name']  # KeyError if 'name' doesn't exist
    email = user_data.get('email')  # This is safe, but name access isn't

    return f"{name} <{email}>"

def divide_numbers(a, b):
    """Division by zero not handled."""
    return a / b  # ZeroDivisionError if b is 0

def access_list_element(data_list, index):
    """No bounds checking."""
    return data_list[index]  # IndexError if index out of bounds

def get_nested_value(data):
    """Deep nesting without safety checks."""
    return data['user']['profile']['settings']['theme']  # Multiple KeyError possibilities

# ==========================================
# TYPE CONVERSION ISSUES
# ==========================================

def convert_to_int(value):
    """Unsafe type conversion."""
    return int(value)  # ValueError if not convertible

def string_concatenation(mixed_data):
    """Unsafe string operations."""
    result = ""
    for item in mixed_data:
        result += str(item)  # May not behave as expected for complex objects
    return result

def numeric_operations(a, b):
    """Missing type validation for math."""
    return a + b  # TypeError if incompatible types

# ==========================================
# RESOURCE MANAGEMENT ISSUES
# ==========================================

def read_file_unsafe(filename):
    """File operations without proper error handling."""
    with open(filename, 'r') as f:  # FileNotFoundError not handled
        return f.read()

def network_request(url):
    """Network calls without timeout or error handling."""
    response = requests.get(url)  # No timeout, may hang forever
    return response.json()  # May fail if not JSON

def database_connection():
    """Database operations without cleanup."""
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    # No try/finally, connection may leak
    cursor.execute("SELECT 1")
    return cursor.fetchone()
