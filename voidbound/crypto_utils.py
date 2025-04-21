import os
import secrets
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class CryptoUtils:
    """Classe para operações criptográficas."""
    
    SALT_SIZE = 16
    IV_SIZE = 16
    ITERATIONS = 100_000
    BLOCK_SIZE = 128  # Em bits
    
    @staticmethod
    def generate_salt() -> bytes:
        """Gera um salt aleatório."""
        return os.urandom(CryptoUtils.SALT_SIZE)
    
    @staticmethod
    def generate_iv() -> bytes:
        """Gera um IV aleatório."""
        return os.urandom(CryptoUtils.IV_SIZE)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Deriva uma chave AES-256 de uma senha usando PBKDF2HMAC."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 (32 bytes)
            salt=salt,
            iterations=CryptoUtils.ITERATIONS
        )
        key = kdf.derive(password.encode('utf-8'))
        return key
    
    @staticmethod
    def encrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
        """Criptografa dados usando AES-256-CBC com preenchimento PKCS7."""
        # Aplicar padding PKCS7
        padder = padding.PKCS7(CryptoUtils.BLOCK_SIZE).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Criptografar com AES-256-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """Descriptografa dados usando AES-256-CBC com preenchimento PKCS7."""
        # Descriptografar com AES-256-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remover padding PKCS7
        unpadder = padding.PKCS7(CryptoUtils.BLOCK_SIZE).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    @staticmethod
    def secure_overwrite(buffer: bytearray) -> None:
        """Sobrescreve um buffer de memória com zeros para remover dados sensíveis."""
        for i in range(len(buffer)):
            buffer[i] = 0