from typing import Optional, Tuple, Dict
import hashlib
import os
from datetime import datetime
import sqlite3
import logging
from .security import SecurityManager

class AuthenticationManager:
    def __init__(self, db_path: str = "secure_storage.db"):
        self.db_path = db_path
        self.security = SecurityManager()
        self._setup_logging()
        self._initialize_database()
        
    def _setup_logging(self):
        logging.basicConfig(
            filename='auth.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _initialize_database(self):
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
            conn.execute("PRAGMA busy_timeout=5000")  # Set busy timeout
            conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes with reasonable safety
            # Create users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    salt TEXT,
                    role TEXT,
                    created_at TEXT,
                    last_login TEXT
                )
            """)
            
            # Create access control table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_control (
                    resource_id TEXT,
                    user_id TEXT,
                    permission_level TEXT,
                    granted_by TEXT,
                    granted_at TEXT,
                    expires_at TEXT,
                    UNIQUE(resource_id, user_id)
                )
            """)
            
            # Create single audit logs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    user_id TEXT,
                    action TEXT,
                    resource_id TEXT,
                    status TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    additional_data TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    action TEXT,
                    timestamp TEXT,
                    details TEXT
                )
            """)
            
    def register(self, username: str, password: str, role: str = "user") -> Tuple[bool, str]:
        try:
            salt = os.urandom(16).hex()
            password_hash = self._hash_password(password, salt)
            user_id = os.urandom(16).hex()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, username, password_hash, salt, role, 
                     datetime.now().isoformat(), None)
                )
            return True, "Registration successful"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
            
    def login(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                cursor = conn.execute(
                    "SELECT id, password_hash, salt, role FROM users WHERE username = ?",
                    (username,)
                )
                user = cursor.fetchone()
                
                if not user:
                    return False, None
                    
                user_id, stored_hash, salt, role = user
                if self._hash_password(password, salt) == stored_hash:
                    # Update last login in a separate connection to avoid locks
                    self._update_last_login(user_id)
                    token = self.security.generate_token(user_id, role)
                    return True, token
                    
                return False, None
        except sqlite3.Error as e:
            logging.error(f"Database error during login: {str(e)}")
            return False, None

    def _update_last_login(self, user_id: str):
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                conn.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now().isoformat(), user_id)
                )
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error updating last login: {str(e)}")
            
    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
        
    def _log_audit(self, user_id: str, action: str, details: str):
        try:
            with sqlite3.connect(self.db_path, timeout=20) as conn:
                conn.execute("""
                    INSERT INTO audit_logs 
                    (timestamp, user_id, action, resource_id, status, ip_address, user_agent, additional_data) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    user_id,
                    action,
                    None,  # resource_id
                    'success',  # status
                    None,  # ip_address
                    None,  # user_agent
                    details  # additional_data
                ))
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database error in audit logging: {str(e)}")