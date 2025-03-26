from pathlib import Path
from typing import Tuple, Dict, List, Optional
import sqlite3
from datetime import datetime
import logging
from .security import SecurityManager
import json
import os

class SecureFileManager:
    def __init__(self, storage_path: str = "secure_storage", db_path: str = "secure_storage.db"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        self.db_path = db_path
        self.security = SecurityManager()
        self._initialize_database()
        self._setup_logging()

    def _initialize_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    filename TEXT,
                    owner_id TEXT,
                    encrypted BOOLEAN,
                    created_at TEXT,
                    modified_at TEXT,
                    file_path TEXT UNIQUE
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_permissions (
                    file_id TEXT,
                    user_id TEXT,
                    permission TEXT,
                    granted_at TEXT,
                    FOREIGN KEY (file_id) REFERENCES files(id),
                    UNIQUE(file_id, user_id)
                )
            """)

    def _setup_logging(self):
        logging.basicConfig(
            filename='file_operations.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _log_operation(self, user_id: str, action: str, file_id: Optional[str], status: str, metadata: Dict = None):
        try:
            with sqlite3.connect(self.db_path, timeout=20) as conn:
                conn.execute("""
                    INSERT INTO audit_logs 
                    (timestamp, user_id, action, resource_id, status, additional_data) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    user_id,
                    action,
                    file_id,
                    status,
                    json.dumps(metadata or {})
                ))
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database error in operation logging: {str(e)}")

    def store_file(self, file_path: str, user_context: Dict, cloud_backup: bool = True) -> Tuple[bool, str]:
        try:
            if not user_context or 'user_id' not in user_context:
                return False, "Invalid user context"
                
            source_path = Path(file_path)
            if not source_path.exists():
                return False, f"File not found: {file_path}"
            
            # Read and encrypt file
            data = source_path.read_bytes()
            encrypted_data = self.security.encrypt_file(data)
            
            # Generate secure file ID and path
            file_id = os.urandom(16).hex()
            dest_path = self.storage_path / f"{file_id}{source_path.suffix}"
            
            # Store encrypted file
            dest_path.write_bytes(encrypted_data)
            
            # Record in database with encryption metadata
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (file_id, source_path.name, user_context['user_id'], True,
                     datetime.now().isoformat(), datetime.now().isoformat(), str(dest_path))
                )
            
            self._log_operation(
                user_context['user_id'],
                'store',
                file_id,
                'success',
                {'encrypted': True}
            )
            
            return True, "File stored successfully"
            
        except Exception as e:
            logging.error(f"File storage error: {str(e)}")
            return False, f"Storage failed: {str(e)}"