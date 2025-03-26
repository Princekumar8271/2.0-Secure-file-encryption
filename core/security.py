from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import jwt
from datetime import datetime, timedelta
import logging
import json
from typing import Tuple, Dict, Optional

class EncryptionContainer:
    def __init__(self, key: bytes, metadata: dict):
        self.key = key
        self.metadata = metadata
        self.cipher = Fernet(key)

    def encrypt_data(self, data: bytes) -> bytes:
        encrypted = self.cipher.encrypt(data)
        container = {
            'data': base64.b64encode(encrypted).decode(),
            'metadata': self.metadata,
            'timestamp': datetime.now().isoformat()
        }
        return base64.b64encode(json.dumps(container).encode())

    def decrypt_data(self, container_data: bytes) -> bytes:
        container = json.loads(base64.b64decode(container_data).decode())
        encrypted_data = base64.b64decode(container['data'].encode())
        return self.cipher.decrypt(encrypted_data)

class SecurityManager:
    def __init__(self):
        self.master_key = os.urandom(32)
        self.secret_key = os.urandom(32)
        self._initialize_encryption()

    def _initialize_encryption(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        self.cipher_suite = MultiFernet([Fernet(key)])

    def create_container(self, file_metadata: dict) -> EncryptionContainer:
        container_key = base64.urlsafe_b64encode(os.urandom(32))
        return EncryptionContainer(container_key, file_metadata)

    def encrypt_file(self, data: bytes, metadata: dict = None) -> bytes:
        """Encrypt file data using container-based encryption"""
        try:
            if metadata is None:
                metadata = {}
            
            # Create hash of original file
            file_hash = hashes.Hash(hashes.SHA256())
            file_hash.update(data)
            metadata['original_hash'] = file_hash.finalize().hex()
            
            # Create encryption container
            container = self.create_container(metadata)
            return container.encrypt_data(data)
            
        except Exception as e:
            logging.error(f"Encryption error: {str(e)}")
            raise

    def decrypt_file(self, container_data: bytes) -> tuple[bytes, dict]:
        """Decrypt file data and return with metadata"""
        try:
            container = json.loads(base64.b64decode(container_data).decode())
            key = base64.urlsafe_b64encode(self.master_key)
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(base64.b64decode(container['data'].encode()))
            return decrypted_data, container['metadata']
        except Exception as e:
            logging.error(f"Decryption error: {str(e)}")
            raise

    def generate_token(self, user_id: str, role: str) -> str:
        """Generate JWT token for user authentication"""
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token: str) -> dict:
        """Verify and decode JWT token"""
        try:
            return jwt.decode(token, self.secret_key, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return None