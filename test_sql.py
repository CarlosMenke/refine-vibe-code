import sqlite3

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

user_input = "admin' OR '1'='1"
# SQL injection vulnerability
cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
