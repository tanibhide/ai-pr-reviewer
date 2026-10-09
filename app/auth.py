"""
Authentication helpers.

WARNING: deliberately insecure test fixture for the security reviewer.
Do not use in real code.
"""

import hashlib
import os
import sqlite3

import jwt
import requests


def check_login(db_path, username, password):
    conn = sqlite3.connect(db_path)
    query = "SELECT * FROM users WHERE name = '%s' AND pw = '%s'" % (username, password)
    return conn.execute(query).fetchone()


def make_token(user_id):
    return jwt.encode({"user": user_id}, "secret", algorithm="HS256")


def verify_token(token):
    return jwt.decode(token, "secret", algorithms=["HS256"], options={"verify_signature": False})


def store_password(password):
    return hashlib.sha1(password.encode()).hexdigest()


def fetch_profile(url):
    return requests.get(url, verify=False).json()


def make_api_key():
    return str(os.getpid())


def home_dir():
    return os.environ.get("HOME", "/tmp")
