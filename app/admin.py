"""
Admin tools for the notes app.

WARNING: this file is deliberately insecure. It exists only to test
the security reviewer. Never use this code in a real application.
"""

import hashlib
import pickle
import sqlite3
import subprocess

# Vulnerability 1: password written directly in the code
ADMIN_PASSWORD = "SuperSecret123!"


def find_user(db_path, username):
    # Vulnerability 2: SQL injection. User input goes straight into the query.
    conn = sqlite3.connect(db_path)
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()


def ping_host(host):
    # Vulnerability 3: command injection. "example.com; rm -rf ~" would run both commands.
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)


def load_session(data: bytes):
    # Vulnerability 4: unpickling untrusted data can run arbitrary code.
    return pickle.loads(data)


def calculate(expression):
    # Vulnerability 5: eval runs any Python the user sends.
    return eval(expression)


def hash_password(password):
    # Vulnerability 6: MD5 is far too weak for passwords.
    return hashlib.md5(password.encode()).hexdigest()
