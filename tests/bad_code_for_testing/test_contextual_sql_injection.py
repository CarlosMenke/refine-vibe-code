"""
Test file specifically for testing Contextual SQLi Audit features.
This file contains patterns where the AI "forgot" to use parameterized queries,
focusing on contextual detection of user input variables and scenarios where
parameterization should have been obvious.

Note: F-strings must be passed directly to execute() for AST detection to work.
"""

import sqlite3
import psycopg2
import mysql.connector
import pymysql

# ==========================================
# CONTEXTUAL SQL INJECTION PATTERNS
# These should trigger enhanced detection
# ==========================================

def authenticate_user(username_input, password_input):
    """Context: User authentication - should obviously be parameterized."""
    # This should be CRITICAL: user input variables in WHERE clause
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username_input}' AND password = '{password_input}'")  # CRITICAL - user input in WHERE
    conn.close()

def search_users(search_term, user_role):
    """Context: Search functionality with multiple user inputs."""
    # Multiple user input variables - should be HIGH severity
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{search_term}%' AND role = '{user_role}'")  # HIGH - multiple user inputs
    conn.close()

def get_user_by_email(user_email, active_status):
    """Context: Email lookup with clear user input."""
    # Variable name clearly indicates user input
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"SELECT id FROM users WHERE email = '{user_email}' AND active = {active_status}")  # CRITICAL - user_email in WHERE
    conn.close()

def update_user_profile(user_id, new_name, new_email):
    """Context: Profile update with multiple user inputs."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET name = '{new_name}', email = '{new_email}' WHERE id = {user_id}")  # HIGH - multiple interpolations in UPDATE
    conn.close()

def delete_inactive_users(cutoff_date, admin_user):
    """Context: Admin operation with date and user parameters."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE last_login < '{cutoff_date}' AND deleted_by = '{admin_user}'")  # CRITICAL - admin operation with user input
    conn.close()

# ==========================================
# DATA PROCESSING WITH OBVIOUS PARAMETERIZATION NEEDS
# ==========================================

def process_user_data(table_name, user_filter, sort_column):
    """Context: Dynamic table/query building - should use parameterization."""
    # Variables suggest dynamic user input
    conn = mysql.connector.connect(host="localhost")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name} WHERE status = '{user_filter}' ORDER BY {sort_column}")  # CRITICAL - dynamic table and column names
    conn.close()

def filter_by_date_range(start_date, end_date, category):
    """Context: Date range filtering with user input."""
    conn = mysql.connector.connect(host="localhost")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM events WHERE date BETWEEN '{start_date}' AND '{end_date}' AND category = '{category}'")  # HIGH - date range with user input
    conn.close()

# ==========================================
# SEARCH FUNCTIONALITY THAT SHOULD USE PREPARED STATEMENTS
# ==========================================

def advanced_search(query_terms, search_type, limit_count):
    """Context: Advanced search with multiple parameters."""
    # Multiple user input variables in complex query
    conn = pymysql.connect(host="localhost")
    with conn.cursor() as cursor:
        cursor.execute(f"""
        SELECT * FROM content
        WHERE MATCH(title, description) AGAINST('{query_terms}')
        AND type = '{search_type}'
        LIMIT {limit_count}
        """)  # CRITICAL - complex search with LIMIT
    conn.close()

def fuzzy_match(input_text, threshold, match_type):
    """Context: Fuzzy matching with user input."""
    conn = pymysql.connect(host="localhost")
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT * FROM items WHERE SIMILARITY(name, '{input_text}') > {threshold} AND type = '{match_type}'")  # HIGH - fuzzy matching with user input
    conn.close()

# ==========================================
# WEB/API CONTEXT PATTERNS
# ==========================================

def process_form_data(form_data, request_params):
    """Context: Web form processing - variables clearly contain user input."""
    conn = psycopg2.connect("dbname=test")
    with conn.cursor() as cursor:
        cursor.execute(f"INSERT INTO submissions (data, params) VALUES ('{form_data}', '{request_params}')")  # CRITICAL - form data in INSERT
    conn.close()

def handle_api_request(api_key, user_query, filters):
    """Context: API request handling with multiple user inputs."""
    conn = sqlite3.connect('api.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM requests WHERE api_key = '{api_key}' AND query = '{user_query}' AND filters = '{filters}'")  # CRITICAL - API parameters in SELECT
    conn.close()

def admin_panel_query(admin_input, table_selection, where_clause):
    """Context: Admin panel - should be extremely careful with parameterization."""
    conn = mysql.connector.connect(user="admin")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_selection} WHERE {where_clause} = '{admin_input}'")  # CRITICAL - admin dynamic query
    conn.close()

# ==========================================
# ENHANCED PATTERN DETECTION CASES
# ==========================================

def batch_process_records(record_ids, status_value, updated_by):
    """Context: Batch processing - list operations should use parameterization."""
    conn = psycopg2.connect("dbname=batch")
    with conn.cursor() as cursor:
        # IN clause with user input - should trigger enhanced pattern detection
        cursor.execute(f"UPDATE records SET status = '{status_value}', updated_by = '{updated_by}' WHERE id IN ({','.join(record_ids)})")  # HIGH - IN clause with user input
    conn.close()

def dynamic_ordering(sort_field, sort_direction, filter_value):
    """Context: Dynamic sorting - ORDER BY with user input."""
    conn = sqlite3.connect('dynamic.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE category = '{filter_value}' ORDER BY {sort_field} {sort_direction}")  # CRITICAL - ORDER BY with user input
    conn.close()

def complex_join_query(user_param1, user_param2, join_table):
    """Context: Complex joins with multiple user parameters."""
    conn = mysql.connector.connect()
    cursor = conn.cursor()
    cursor.execute(f"""
    SELECT u.*, p.*
    FROM users u
    JOIN {join_table} p ON u.id = p.user_id
    WHERE u.status = '{user_param1}' AND p.type = '{user_param2}'
    """)  # CRITICAL - complex join with user input
    conn.close()

# ==========================================
# SUBTLE CASES THAT SHOULD STILL BE DETECTED
# ==========================================

def generate_report(report_type, date_from, date_to, group_by):
    """Context: Report generation - user parameters in aggregation."""
    conn = psycopg2.connect("dbname=reports")
    with conn.cursor() as cursor:
        cursor.execute(f"""
        SELECT {group_by}, COUNT(*) as total
        FROM events
        WHERE created_at BETWEEN '{date_from}' AND '{date_to}'
        AND type = '{report_type}'
        GROUP BY {group_by}
        """)  # CRITICAL - aggregation with user input
    conn.close()

def conditional_query_builder(condition_type, value1, value2, operator):
    """Context: Dynamic query building based on conditions."""
    conn = sqlite3.connect('conditional.db')
    cursor = conn.cursor()

    # Dynamic condition building - very dangerous
    if condition_type == 'range':
        cursor.execute(f"SELECT * FROM data WHERE value BETWEEN '{value1}' AND '{value2}'")  # CRITICAL - dynamic condition
    else:
        cursor.execute(f"SELECT * FROM data WHERE value {operator} '{value1}'")  # CRITICAL - dynamic operator

    conn.close()

# ==========================================
# MIXED SAFE/UNSAFE PATTERNS
# ==========================================

def mixed_pattern_example(user_input, safe_param):
    """Context: Mix of parameterized and non-parameterized patterns."""
    conn = sqlite3.connect('mixed.db')
    cursor = conn.cursor()

    # First query: should be safe (parameterized)
    cursor.execute("SELECT * FROM users WHERE id = ?", (safe_param,))

    # Second query: should be detected as contextual SQLi
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")  # HIGH - mixed with safe pattern above

    conn.close()

def gradual_degradation_example(initial_safe, later_unsafe):
    """Context: Code that starts safe but becomes unsafe."""
    conn = psycopg2.connect("dbname=gradual")
    with conn.cursor() as cursor:
        # Start with safe pattern
        cursor.execute("SELECT * FROM items WHERE category = %s", (initial_safe,))

        # Later becomes unsafe - should still be detected
        cursor.execute(f"SELECT * FROM items WHERE name = '{later_unsafe}'")  # HIGH - degradation from safe to unsafe

    conn.close()