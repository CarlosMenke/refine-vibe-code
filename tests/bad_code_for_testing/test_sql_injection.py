"""
Test file with SQL injection vulnerabilities that should be detected
by the SQL injection checker. This file contains various patterns of
SQL injection vulnerabilities including raw string interpolation,
missing parameterization, and unsafe string operations.
"""

import sqlite3
import psycopg2
import pymysql
import mysql.connector

# ==========================================
# VULNERABLE PATTERNS - Should be detected
# ==========================================

def vulnerable_sqlite_f_string():
    """Vulnerable: f-string in SQL query."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # This should be flagged as vulnerable
    user_input = "admin'; DROP TABLE users; --"
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)  # HIGH severity - f-string interpolation

    conn.close()

def vulnerable_sqlite_string_concat():
    """Vulnerable: String concatenation in SQL."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_id = "1' OR '1'='1"
    # This should be flagged as vulnerable
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")  # HIGH severity

    conn.close()

def vulnerable_sqlite_percent_formatting():
    """Vulnerable: Old-style string formatting."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin"
    password = "password' OR '1'='1"

    # This should be flagged as vulnerable
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cursor.execute(query)  # HIGH severity

    conn.close()

def vulnerable_sqlite_format_method():
    """Vulnerable: .format() method usage."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    table_name = "users"
    column = "username"
    value = "admin'; DROP TABLE users; --"

    # This should be flagged as vulnerable
    query = "SELECT * FROM {} WHERE {} = '{}'".format(table_name, column, value)
    cursor.execute(query)  # HIGH severity

    conn.close()

def vulnerable_postgres_interpolation():
    """Vulnerable: Raw string interpolation with psycopg2."""
    # Assuming connection exists
    conn = psycopg2.connect("dbname=test user=test")
    cursor = conn.cursor()

    user_email = "user@example.com' UNION SELECT password FROM admin --"

    # This should be flagged as vulnerable
    cursor.execute(f"SELECT * FROM users WHERE email = '{user_email}'")  # HIGH severity

    conn.close()

def vulnerable_mysql_interpolation():
    """Vulnerable: Raw string interpolation with MySQL."""
    # Assuming connection exists
    conn = mysql.connector.connect(host="localhost", user="test", password="test")
    cursor = conn.cursor()

    search_term = "test%' UNION SELECT * FROM information_schema.tables --"

    # This should be flagged as vulnerable
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)  # HIGH severity

    conn.close()

def vulnerable_pymysql_format():
    """Vulnerable: .format() with pymysql."""
    conn = pymysql.connect(host="localhost", user="test", password="test", db="test")
    cursor = conn.cursor()

    username = "admin"
    user_id = "1' OR '1'='1"

    # This should be flagged as vulnerable
    cursor.execute("SELECT * FROM users WHERE username = '{}' AND id = '{}'".format(username, user_id))  # HIGH severity

    conn.close()

def vulnerable_complex_query():
    """Vulnerable: Complex query with multiple interpolations."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    table = "users"
    column1 = "username"
    column2 = "email"
    value1 = "admin"
    value2 = "admin@example.com' OR email LIKE '%@%' --"

    # This should be flagged as vulnerable - multiple interpolation points
    query = f"INSERT INTO {table} ({column1}, {column2}) VALUES ('{value1}', '{value2}')"
    cursor.execute(query)  # HIGH severity

    conn.close()

# ==========================================
# SAFE PATTERNS - Should NOT be flagged
# ==========================================

def safe_parameterized_query():
    """Safe: Using parameterized queries."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"

    # This should NOT be flagged - proper parameterization
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))

    conn.close()

def safe_named_parameters():
    """Safe: Using named parameters."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin"
    user_id = 1

    # This should NOT be flagged - named parameters
    cursor.execute("SELECT * FROM users WHERE username = :username AND id = :id",
                   {"username": username, "id": user_id})

    conn.close()

def safe_postgres_parameters():
    """Safe: PostgreSQL parameterized query."""
    conn = psycopg2.connect("dbname=test user=test")
    cursor = conn.cursor()

    user_email = "user@example.com"

    # This should NOT be flagged - proper parameterization
    cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))

    conn.close()

def safe_static_query():
    """Safe: Static SQL query with no user input."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # This should NOT be flagged - no user input
    cursor.execute("SELECT COUNT(*) FROM users")

    conn.close()

def safe_orm_usage():
    """Safe: Using ORM (simulated)."""
    # This would be safe if using SQLAlchemy or similar ORM
    # For testing purposes, we'll simulate ORM usage
    user_input = "admin"

    # Simulating ORM query - should NOT be flagged
    query = "SELECT * FROM users WHERE username = %s"  # This is just a string, not actual execution
    # In real ORM: User.query.filter_by(username=user_input).all()

# ==========================================
# EDGE CASES
# ==========================================

def edge_case_multiline_query():
    """Edge case: Multiline query with interpolation."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin"
    password = "secret"

    # This should be flagged - multiline f-string
    query = f"""
    SELECT * FROM users
    WHERE username = '{username}'
    AND password = '{password}'
    """
    cursor.execute(query)  # HIGH severity

    conn.close()

def edge_case_function_call_in_query():
    """Edge case: Function call within interpolated query."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin"

    # This should be flagged - function call in f-string
    query = f"SELECT * FROM users WHERE username = '{user_input.upper()}'"
    cursor.execute(query)  # HIGH severity

    conn.close()
