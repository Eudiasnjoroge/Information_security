#!/usr/bin/env python3
"""
Identity Theft Detection & Prevention System (Intermediate)

Features:
- SQLite database to store users, login attempts, and alerts
- Password hashing with SHA-256 + per-user salt (via HMAC)
- Detection rules:
  * Repeated failed logins within a short time window
  * Login from an unusual country for that user
  * Large data export event flag

Usage: run the script. The `main()` function contains a demo simulation.

Author: Your Name
Course: Computer & Information Security
"""

import sqlite3
import hashlib
import os
import time
import hmac
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = "identity_system.db"
FAILED_LOGIN_THRESHOLD = 5          # failed attempts to trigger an alert
FAILED_LOGIN_WINDOW_SEC = 300       # time window in seconds (5 minutes)
LARGE_EXPORT_THRESHOLD = 1000       # arbitrary threshold for export size (records)

# -----------------------------
# Database helpers
# -----------------------------
def get_db_connection(path: str = DB_PATH):
    """Return a sqlite3 connection (creates DB if missing)."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn: sqlite3.Connection):
    """Create tables if they don't exist."""
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        home_country TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp TEXT,
        success INTEGER,
        ip TEXT,
        country TEXT,
        event_type TEXT,
        details TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp TEXT,
        alert_type TEXT,
        description TEXT,
        handled INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()

# -----------------------------
# Security helpers
# -----------------------------
def generate_salt(length: int = 16) -> str:
    return os.urandom(length).hex()

def hash_password(password: str, salt: str) -> str:
    """Return hex SHA-256 hash of password+salt using HMAC."""
    h = hashlib.sha256()
    # Use HMAC with salt for keyed hashing
    h.update(hmac.new(salt.encode(), password.encode(), hashlib.sha256).digest())
    return h.hexdigest()

# -----------------------------
# User management
# -----------------------------
def add_user(conn: sqlite3.Connection, username: str, password: str, home_country: Optional[str] = None):
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, home_country) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, home_country),
        )
        conn.commit()
        print(f"[INFO] User '{username}' added.")
    except sqlite3.IntegrityError:
        print(f"[WARN] User '{username}' already exists.")

def get_user(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

# -----------------------------
# Event logging
# -----------------------------
def log_event(conn: sqlite3.Connection, user_id: Optional[int], success: bool, ip: str, country: str, event_type: str = "login", details: str = ""):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO login_events (user_id, timestamp, success, ip, country, event_type, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, datetime.utcnow().isoformat(), int(success), ip, country, event_type, details),
    )
    conn.commit()

# -----------------------------
# Alerting
# -----------------------------
def create_alert(conn: sqlite3.Connection, user_id: Optional[int], alert_type: str, description: str):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO alerts (user_id, timestamp, alert_type, description) VALUES (?, ?, ?, ?)",
        (user_id, datetime.utcnow().isoformat(), alert_type, description),
    )
    conn.commit()
    print(f"[ALERT] {alert_type}: {description}")

# -----------------------------
# Detection rules
# -----------------------------
def check_failed_login_burst(conn: sqlite3.Connection, user_id: int):
    """Detect if many failed logins in a short window."""
    cur = conn.cursor()
    window_start = datetime.utcnow() - timedelta(seconds=FAILED_LOGIN_WINDOW_SEC)
    cur.execute(
        "SELECT COUNT(*) AS cnt FROM login_events WHERE user_id = ? AND success = 0 AND timestamp >= ?",
        (user_id, window_start.isoformat()),
    )
    row = cur.fetchone()
    cnt = row["cnt"] if row else 0
    if cnt >= FAILED_LOGIN_THRESHOLD:
        create_alert(conn, user_id, "FailedLoginBurst", f"{cnt} failed logins in the last {FAILED_LOGIN_WINDOW_SEC} seconds")

def check_unusual_location(conn: sqlite3.Connection, user_id: int, country: str):
    """Flag if country differs from user's recorded home_country."""
    cur = conn.cursor()
    cur.execute("SELECT home_country FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    home_country = row["home_country"] if row else None
    if home_country and country != home_country:
        create_alert(conn, user_id, "UnusualLocation", f"Login from {country} (home: {home_country})")

def check_large_export(conn: sqlite3.Connection, user_id: int, export_size: int):
    if export_size >= LARGE_EXPORT_THRESHOLD:
        create_alert(conn, user_id, "LargeExport", f"Export of size {export_size} detected")

# -----------------------------
# Authentication flow
# -----------------------------
def attempt_login(conn: sqlite3.Connection, username: str, password: str, ip: str, country: str):
    user = get_user(conn, username)
    user_id = user["id"] if user else None

    if not user:
        # Log as failed attempt for unknown user
        log_event(conn, None, False, ip, country, event_type="login", details=f"unknown_user:{username}")
        print("[INFO] Unknown username")
        return False

    expected_hash = user["password_hash"]
    salt = user["salt"]
    candidate_hash = hash_password(password, salt)

    if hmac.compare_digest(candidate_hash, expected_hash):
        # Success
        log_event(conn, user_id, True, ip, country, event_type="login", details="successful_login")
        print(f"[INFO] Successful login for {username}")
        # Check location-based heuristic
        check_unusual_location(conn, user_id, country)
        return True
    else:
        # Failed login
        log_event(conn, user_id, False, ip, country, event_type="login", details="bad_password")
        print(f"[WARN] Failed login for {username}")
        # Check for burst after logging
        check_failed_login_burst(conn, user_id)
        return False

# -----------------------------
# Utility: pretty print alerts
# -----------------------------
def list_alerts(conn: sqlite3.Connection, only_unhandled: bool = True):
    cur = conn.cursor()
    if only_unhandled:
        cur.execute("SELECT * FROM alerts WHERE handled = 0 ORDER BY timestamp DESC")
    else:
        cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = cur.fetchall()
    for r in rows:
        print(f"[{r['timestamp']}] {r['alert_type']} (user_id={r['user_id']}): {r['description']}")

# -----------------------------
# Demo / simulation
# -----------------------------
def main():
    # Remove DB for demo repeatability
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_db_connection()
    init_db(conn)

    # Add sample users
    add_user(conn, "alice", "S3cureP@ss!", home_country="USA")
    add_user(conn, "bob", "P4ssword!", home_country="KENYA")

    # Normal login
    attempt_login(conn, "alice", "S3cureP@ss!", ip="192.0.2.2", country="USA")

    # Failed login attempts (simulate credential stuffing)
    for i in range(FAILED_LOGIN_THRESHOLD + 1):
        attempt_login(conn, "bob", "wrongpass", ip=f"198.51.100.{i}", country="KENYA")
        time.sleep(0.5)  # short gap between attempts

    # Login from unusual country
    attempt_login(conn, "alice", "S3cureP@ss!", ip="203.0.113.5", country="RUS")

    # Simulate large export event
    # In a real app this would be an event type from a data export process
    log_event(conn, 1, True, ip="192.0.2.2", country="USA", event_type="export", details="export_records:1500")
    check_large_export(conn, 1, export_size=1500)

    print("\n=== Alerts ===")
    list_alerts(conn)

    conn.close()

if __name__ == "__main__":
    main()

