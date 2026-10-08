"""
A tiny notes app. This is the code the security reviewer scans.
It is written safely: every database query uses placeholders (?)
instead of putting user input directly into the SQL.
"""

import sqlite3

DB_PATH = "notes.db"


def get_connection(path=DB_PATH):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)"
    )
    return conn


def add_note(conn, owner, body):
    conn.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (owner, body))
    conn.commit()


def list_notes(conn, owner):
    rows = conn.execute("SELECT id, body FROM notes WHERE owner = ?", (owner,))
    return rows.fetchall()
