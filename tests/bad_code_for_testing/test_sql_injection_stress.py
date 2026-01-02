"""
Comprehensive stress test file for SQL injection checker.
Tests complex scenarios, edge cases, false positives, and various injection techniques.
"""

import sqlite3
import psycopg2
import pymysql
import mysql.connector
from typing import List, Dict, Any, Optional
import os

# ==========================================
# BASIC VULNERABLE PATTERNS (SHOULD BE DETECTED)
# ==========================================

def vulnerable_basic_f_string():
    """Basic f-string interpolation."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"
    # HIGH severity - f-string with user input
    cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")

    conn.close()

def vulnerable_basic_format():
    """Basic .format() interpolation."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"
    # HIGH severity - format with user input
    cursor.execute("SELECT * FROM users WHERE username = '{}'".format(user_input))

    conn.close()

def vulnerable_basic_percent():
    """Basic % formatting."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"
    # HIGH severity - % formatting with user input
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % user_input)

    conn.close()

# ==========================================
# COMPLEX MULTI-CLAUSE INJECTIONS
# ==========================================

def vulnerable_complex_where_clauses():
    """Multiple WHERE conditions with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin"
    email = "admin@example.com' UNION SELECT password FROM admin --"
    user_id = "1' OR '1'='1"
    status = "active"

    # Multiple interpolated variables in complex WHERE
    query = f"""
    SELECT * FROM users
    WHERE username = '{username}'
      AND email = '{email}'
      AND id = '{user_id}'
      AND status = '{status}'
    """
    # CRITICAL - multiple user inputs in complex query
    cursor.execute(query)

    conn.close()

def vulnerable_nested_queries():
    """Nested subqueries with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; SELECT * FROM information_schema.tables; --"
    category = "electronics"

    # Nested query with injection
    query = f"""
    SELECT * FROM products
    WHERE category = '{category}'
      AND id IN (
        SELECT product_id FROM user_favorites
        WHERE user_id = (
          SELECT id FROM users WHERE username = '{user_input}'
        )
      )
    """
    # CRITICAL - nested subqueries with injection
    cursor.execute(query)

    conn.close()

def vulnerable_join_injections():
    """JOIN clauses with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    username = "admin"
    table_name = "users; DROP TABLE sensitive_data; --"

    # Injection in JOIN clause
    query = f"""
    SELECT u.*, p.permissions
    FROM users u
    JOIN {table_name} p ON u.id = p.user_id
    WHERE u.username = '{username}'
    """
    # CRITICAL - table name injection in JOIN
    cursor.execute(query)

    conn.close()

# ==========================================
# ADVANCED INJECTION TECHNIQUES
# ==========================================

def vulnerable_union_based():
    """UNION-based injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    search_term = "test' UNION SELECT username, password FROM admin --"

    # UNION injection
    query = f"SELECT name, price FROM products WHERE name LIKE '%{search_term}%'"
    # CRITICAL - UNION-based injection
    cursor.execute(query)

    conn.close()

def vulnerable_blind_injections():
    """Blind SQL injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_id = "1' AND (SELECT COUNT(*) FROM users) > 0 --"

    # Blind injection - no visible results but still dangerous
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    # CRITICAL - blind injection
    cursor.execute(query)

    conn.close()

def vulnerable_time_based():
    """Time-based injections (simulated)."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "1' AND SLEEP(5) --"

    # Time-based injection (would cause delays)
    query = f"SELECT * FROM users WHERE id = '{user_input}'"
    # CRITICAL - time-based injection
    cursor.execute(query)

    conn.close()

def vulnerable_error_based():
    """Error-based injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "1' AND 1=CONVERT(int, 'test') --"

    # Error-based injection (would cause SQL errors)
    query = f"SELECT * FROM users WHERE id = '{user_input}'"
    # CRITICAL - error-based injection
    cursor.execute(query)

    conn.close()

# ==========================================
# STORED PROCEDURE INJECTIONS
# ==========================================

def vulnerable_stored_procedures():
    """Stored procedure calls with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    proc_name = "get_user_data'; DROP TABLE users; --"
    user_id = "1"

    # Stored procedure injection
    query = f"CALL {proc_name}({user_id})"
    # CRITICAL - stored procedure name injection
    cursor.execute(query)

    conn.close()

def vulnerable_dynamic_procedures():
    """Dynamic stored procedure execution."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    proc_params = "1); DROP TABLE users; --"

    # Dynamic procedure call
    query = f"EXEC sp_get_user @user_id = {proc_params}"
    # CRITICAL - procedure parameter injection
    cursor.execute(query)

    conn.close()

# ==========================================
# ORM-LIKE PATTERNS (FALSE POSITIVES)
# ==========================================

def safe_orm_patterns():
    """Patterns that look like injections but are safe ORM usage."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # These should NOT be flagged - they look like ORM usage

    # Simulated ORM query building
    table_name = "users"  # Not user input
    column_name = "username"  # Not user input
    user_input = "admin"

    # Safe parameterized query
    cursor.execute(f"SELECT * FROM {table_name} WHERE {column_name} = ?", (user_input,))

    # Safe named parameters
    cursor.execute(f"SELECT * FROM {table_name} WHERE {column_name} = :username",
                  {"username": user_input})

    conn.close()

def safe_query_builder():
    """Safe query builder pattern."""
    class SafeQueryBuilder:
        def __init__(self, table):
            self.table = table  # Not user input
            self.conditions = []

        def where(self, column, value):
            # Column name is controlled, value is parameterized
            self.conditions.append(f"{column} = ?")
            self.values.append(value)
            return self

        def build(self):
            where_clause = " AND ".join(self.conditions)
            return f"SELECT * FROM {self.table} WHERE {where_clause}"

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin"

    # Safe query builder usage
    builder = SafeQueryBuilder("users")
    query = builder.where("username", user_input).build()
    cursor.execute(query, builder.values)  # Should NOT be flagged

    conn.close()

# ==========================================
# EDGE CASES AND BOUNDARY CONDITIONS
# ==========================================

def edge_case_empty_strings():
    """Empty string injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    empty_input = ""

    # Empty string - should this be flagged?
    query = f"SELECT * FROM users WHERE username = '{empty_input}'"
    cursor.execute(query)

    conn.close()

def edge_case_whitespace():
    """Whitespace handling in injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Injection with extra whitespace
    user_input = "  admin'  ;  DROP TABLE users; --  "

    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    # Should still be detected despite extra whitespace
    cursor.execute(query)

    conn.close()

def edge_case_multiline_injections():
    """Multiline injection attempts."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = """admin'
    UNION SELECT
    password FROM users --
    """

    # Multiline injection
    query = f"""
    SELECT * FROM users
    WHERE username = '{user_input}'
    """
    # CRITICAL - multiline injection
    cursor.execute(query)

    conn.close()

def edge_case_unicode_injections():
    """Unicode and special character injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Unicode injection attempts
    user_input = "admin' UNION SELECT password FROM users -- 😀"

    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    # Should be detected despite unicode
    cursor.execute(query)

    conn.close()

# ==========================================
# COMPLEX STRING OPERATIONS
# ==========================================

def vulnerable_string_concatenation():
    """Various string concatenation methods."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"

    # Method 1: Simple concatenation
    query1 = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query1)  # HIGH severity

    # Method 2: Join with list
    query2 = "".join(["SELECT * FROM users WHERE username = '", user_input, "'"])
    cursor.execute(query2)  # HIGH severity

    # Method 3: String addition
    base_query = "SELECT * FROM users WHERE username = '"
    full_query = base_query + user_input + "'"
    cursor.execute(full_query)  # HIGH severity

    conn.close()

def vulnerable_template_strings():
    """Template string injections."""
    from string import Template

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"

    # String Template usage
    query_template = Template("SELECT * FROM users WHERE username = '$username'")
    query = query_template.substitute(username=user_input)
    # HIGH severity - template substitution with user input
    cursor.execute(query)

    conn.close()

# ==========================================
# DYNAMIC TABLE/COLUMN NAMES
# ==========================================

def vulnerable_dynamic_table_names():
    """Dynamic table and column names."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # These should be CRITICAL - table/column name injection

    table_name = "users; DROP TABLE sensitive_data; --"
    column_name = "username; SELECT password FROM admin; --"

    # Table name injection
    query1 = f"SELECT * FROM {table_name}"
    cursor.execute(query1)

    # Column name injection
    query2 = f"SELECT {column_name} FROM users"
    cursor.execute(query2)

    # Both table and column
    query3 = f"SELECT {column_name} FROM {table_name}"
    cursor.execute(query3)

    conn.close()

def vulnerable_alter_table():
    """ALTER TABLE injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    table_name = "users' ADD COLUMN password_hash TEXT; --"

    # ALTER TABLE injection
    query = f"ALTER TABLE {table_name} ADD COLUMN created_at TIMESTAMP"
    # CRITICAL - ALTER TABLE injection
    cursor.execute(query)

    conn.close()

# ==========================================
# BATCH OPERATIONS AND MULTIPLE QUERIES
# ==========================================

def vulnerable_batch_operations():
    """Batch insert/update with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_inputs = [
        "user1",
        "user2'; DROP TABLE users; --",
        "user3"
    ]

    # Batch insert with injection
    for username in user_inputs:
        query = f"INSERT INTO users (username) VALUES ('{username}')"
        # HIGH severity - batch operation with injection
        cursor.execute(query)

    conn.close()

def vulnerable_multiple_statements():
    """Multiple statement execution."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Multiple statements in one execution
    malicious_input = "admin'); DROP TABLE users; SELECT * FROM admin WHERE ('1'='1"

    query = f"""
    BEGIN;
    INSERT INTO audit_log (username, action) VALUES ('{malicious_input}', 'login');
    COMMIT;
    """
    # CRITICAL - multiple statement injection
    cursor.executescript(query)

    conn.close()

# ==========================================
# CONTEXT-AWARE INJECTIONS
# ==========================================

def vulnerable_in_comments():
    """Injections hidden in comments."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Injection in SQL comment
    user_input = "admin' /* injected comment */ UNION SELECT password FROM users --"

    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    # Should still be detected despite comments
    cursor.execute(query)

    conn.close()

def vulnerable_with_parentheses():
    """Injections using parentheses."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = ") UNION SELECT password FROM users --"

    # Injection using parentheses
    query = f"SELECT * FROM users WHERE (username = '{user_input}')"
    # CRITICAL - parentheses-based injection
    cursor.execute(query)

    conn.close()

# ==========================================
# DIFFERENT SQL DIALECTS
# ==========================================

def vulnerable_postgres_specific():
    """PostgreSQL-specific injections."""
    # Assuming psycopg2 connection
    conn = psycopg2.connect("dbname=test user=test")
    cursor = conn.cursor()

    user_input = "admin'; SELECT pg_sleep(10); --"

    # PostgreSQL-specific functions
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    # CRITICAL - PostgreSQL-specific injection
    cursor.execute(query)

    conn.close()

def vulnerable_mysql_specific():
    """MySQL-specific injections."""
    conn = mysql.connector.connect(host="localhost", user="test")
    cursor = conn.cursor()

    user_input = "admin'; LOAD_FILE('/etc/passwd'); --"

    # MySQL-specific functions
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    # CRITICAL - MySQL-specific injection
    cursor.execute(query)

    conn.close()

# ==========================================
# SECOND-ORDER INJECTIONS
# ==========================================

def vulnerable_second_order():
    """Second-order SQL injection."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # First, insert malicious data
    malicious_username = "admin' --"
    cursor.execute("INSERT INTO users (username, email) VALUES (?, ?)",
                  (malicious_username, "admin@example.com"))

    # Later, use that data in a query (this would be vulnerable in stored data)
    cursor.execute("SELECT * FROM users WHERE username = 'admin' --' AND active = 1")

    conn.close()

# ==========================================
# ORM MISUSE PATTERNS
# ==========================================

def vulnerable_orm_like_patterns():
    """Patterns that misuse ORM-like constructs."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # These look like safe ORM usage but aren't

    class UnsafeQueryBuilder:
        def __init__(self):
            self.query_parts = []

        def where(self, condition):
            # Direct string concatenation - UNSAFE
            self.query_parts.append(f"WHERE {condition}")
            return self

        def build(self):
            return "SELECT * FROM users " + " ".join(self.query_parts)

    user_input = "username = 'admin' OR 1=1"
    builder = UnsafeQueryBuilder()
    query = builder.where(user_input).build()
    # HIGH severity - unsafe query building
    cursor.execute(query)

    conn.close()

# ==========================================
# COMPLEX CONDITIONAL LOGIC
# ==========================================

def vulnerable_conditional_queries():
    """Conditional query building with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin"
    include_email = True
    email_filter = "'; DROP TABLE users; --"

    # Conditional query building
    query = "SELECT * FROM users WHERE username = ?"
    params = [user_input]

    if include_email:
        query += f" AND email = '{email_filter}'"  # Injection here!
        # HIGH severity - conditional injection

    cursor.execute(query, params)

    conn.close()

# ==========================================
# PREPARED STATEMENT BYPASS ATTEMPTS
# ==========================================

def attempted_prepared_bypass():
    """Attempts to bypass prepared statements."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # These should still be flagged as they attempt injection

    # Attempt 1: Mixing prepared and interpolated
    user_input = "admin'; DROP TABLE users; --"
    query = f"SELECT * FROM users WHERE username = '{user_input}' AND active = ?"
    # HIGH severity - mixed prepared/interpolated
    cursor.execute(query, (1,))

    # Attempt 2: Dynamic table names in prepared statements
    table_name = "users; DROP TABLE sensitive_data; --"
    query = f"SELECT * FROM {table_name} WHERE id = ?"
    # CRITICAL - table name injection with prepared statement
    cursor.execute(query, (1,))

    conn.close()

# ==========================================
# LOGGING AND DEBUG QUERIES
# ==========================================

def vulnerable_debug_queries():
    """Debug and logging queries with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; SELECT * FROM information_schema.tables; --"

    # Debug query that could be vulnerable
    debug_query = f"SELECT COUNT(*) FROM users WHERE username = '{user_input}'"
    # HIGH severity - debug query with injection
    cursor.execute(debug_query)

    # Logging the query (dangerous)
    print(f"Executing query: {debug_query}")

    conn.close()

# ==========================================
# CACHED QUERY INJECTIONS
# ==========================================

def vulnerable_cached_queries():
    """Cached query patterns with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Simulated query cache
    query_cache = {}

    def get_user_query(username):
        cache_key = f"user_query_{username}"
        if cache_key not in query_cache:
            # Building and caching a vulnerable query
            query = f"SELECT * FROM users WHERE username = '{username}'"
            query_cache[cache_key] = query
        return query_cache[cache_key]

    malicious_username = "admin'; DROP TABLE users; --"
    query = get_user_query(malicious_username)
    # HIGH severity - cached injection
    cursor.execute(query)

    conn.close()

# ==========================================
# ASYNC AND CONCURRENT QUERIES
# ==========================================

import asyncio
import threading

async def vulnerable_async_queries():
    """Async query execution with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"

    # Async query with injection
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    # HIGH severity - async injection
    cursor.execute(query)

    await asyncio.sleep(0.1)  # Simulate async operation
    conn.close()

def vulnerable_threaded_queries():
    """Multi-threaded queries with injections."""
    def execute_query(user_input):
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()

        query = f"SELECT * FROM users WHERE username = '{user_input}'"
        # HIGH severity - threaded injection
        cursor.execute(query)

        conn.close()

    # Start multiple threads with malicious input
    threads = []
    for i in range(5):
        malicious_input = f"admin{i}'; DROP TABLE users; --"
        thread = threading.Thread(target=execute_query, args=(malicious_input,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# ==========================================
# COMPLEX NESTED STRUCTURES
# ==========================================

def vulnerable_nested_function_calls():
    """Injections in nested function calls."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    def build_where_clause(field, value):
        # Vulnerable function that builds SQL
        return f"{field} = '{value}'"

    def build_query(*conditions):
        # Another vulnerable function
        where_clause = " AND ".join(conditions)
        return f"SELECT * FROM users WHERE {where_clause}"

    user_input = "admin'; DROP TABLE users; --"
    malicious_condition = build_where_clause("username", user_input)
    query = build_query(malicious_condition, "active = 1")

    # HIGH severity - nested function injection
    cursor.execute(query)

    conn.close()

# ==========================================
# EXCEPTION HANDLING INJECTIONS
# ==========================================

def vulnerable_exception_handling():
    """Injections in exception handling."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"

    try:
        query = f"SELECT * FROM users WHERE username = '{user_input}'"
        # HIGH severity - injection in try block
        cursor.execute(query)
    except Exception as e:
        # Dangerous: logging the failed query
        print(f"Query failed: {query}")
        # Even more dangerous: trying to fix and re-execute
        fixed_query = query.replace("'", "''")  # Naive escaping
        cursor.execute(fixed_query)

    conn.close()

# ==========================================
# CONFIGURATION-DRIVEN QUERIES
# ==========================================

def vulnerable_config_driven_queries():
    """Queries built from configuration with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Simulated configuration (could come from user input)
    config = {
        "table": "users",
        "fields": ["username", "email"],
        "where_conditions": ["username = 'admin'; DROP TABLE users; --'"]
    }

    # Building query from config
    fields = ", ".join(config["fields"])
    where_clause = " AND ".join(config["where_conditions"])
    query = f"SELECT {fields} FROM {config['table']} WHERE {where_clause}"

    # CRITICAL - config-driven injection
    cursor.execute(query)

    conn.close()

# ==========================================
# PLUGIN AND EXTENSION QUERIES
# ==========================================

def vulnerable_plugin_queries():
    """Queries from plugins/extensions with injections."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    def load_plugin_query(plugin_name, user_input):
        # Simulated plugin loading
        if plugin_name == "user_search":
            return f"SELECT * FROM users WHERE username LIKE '%{user_input}%'"
        return "SELECT 1"

    # Plugin-based query execution
    malicious_plugin_input = "admin%' UNION SELECT password FROM admin --"
    query = load_plugin_query("user_search", malicious_plugin_input)

    # HIGH severity - plugin injection
    cursor.execute(query)

    conn.close()

# ==========================================
# MACHINE LEARNING AND AI-GENERATED QUERIES
# ==========================================

def vulnerable_ai_generated_queries():
    """Queries that might be generated by AI/ML systems."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Simulated AI-generated query with injection vulnerability
    ai_generated_query = """
    SELECT users.username, users.email, orders.total
    FROM users
    JOIN orders ON users.id = orders.user_id
    WHERE users.username = '{}'
    """.format("admin'; DROP TABLE orders; --")

    # HIGH severity - AI-generated injection
    cursor.execute(ai_generated_query)

    conn.close()

# ==========================================
# TESTING AND MOCKING PATTERNS
# ==========================================

def vulnerable_test_queries():
    """Test code with injections (should still be flagged)."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    def test_sql_injection(user_input):
        """Test function that intentionally tests SQL injection."""
        # Even in tests, this should be flagged
        query = f"SELECT * FROM users WHERE username = '{user_input}'"
        cursor.execute(query)
        return cursor.fetchall()

    # Test with malicious input
    malicious_input = "admin'; DROP TABLE users; --"
    results = test_sql_injection(malicious_input)

    conn.close()

def vulnerable_mock_database():
    """Mock database implementations with injections."""
    class MockDatabase:
        def __init__(self):
            self.data = {}

        def execute(self, query):
            # Mock execution - but still vulnerable to injection concepts
            if "DROP TABLE" in query:
                print("Mock: Would drop table")
            elif "SELECT" in query:
                print(f"Mock: Would execute SELECT: {query}")
            return []

    db = MockDatabase()
    user_input = "admin'; DROP TABLE users; --"
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    # Should still be flagged even in mock
    db.execute(query)

