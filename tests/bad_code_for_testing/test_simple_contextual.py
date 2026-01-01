"""
Simple test file for contextual SQL injection detection.
"""

import sqlite3

def vulnerable_user_input_in_where():
    """Should be CRITICAL: user input in WHERE clause."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin'; DROP TABLE users; --"
    # This should trigger contextual detection - f-string passed directly
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")  # CRITICAL - username in WHERE clause

    conn.close()

def vulnerable_multiple_user_vars():
    """Should be HIGH: multiple user input variables."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin"
    user_id = "1' OR '1'='1"

    # Multiple interpolations with user variables
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND id = '{user_id}'")  # HIGH - multiple user variables

    conn.close()

def vulnerable_search_pattern():
    """Should be HIGH: search with user input."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    search_term = "test%' UNION SELECT * FROM information_schema.tables --"

    # LIKE with user input
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search_term}%'")  # HIGH - LIKE with user input

    conn.close()

def vulnerable_format_with_user_vars():
    """Should be HIGH: .format() with user variables."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin"
    user_id = "1' OR '1'='1"

    # .format() with user variables - should trigger enhanced pattern
    cursor.execute("SELECT * FROM users WHERE username = '{}' AND id = '{}'".format(username, user_id))  # HIGH severity

    conn.close()

def vulnerable_complex_context():
    """Should trigger enhanced pattern detection."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Complex scenario with clear user input variables
    user_email = "user@example.com' UNION SELECT password FROM admin --"
    user_id = "1' OR '1'='1"
    search_query = "test"

    # Multiple clauses with user input
    query = f"SELECT * FROM users WHERE email = '{user_email}' AND id = '{user_id}' AND name LIKE '%{search_query}%'"
    cursor.execute(query)  # CRITICAL - complex multi-clause query

    conn.close()
