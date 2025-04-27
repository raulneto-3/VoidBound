import os
import secrets
import json
import base64
from typing import Tuple, Optional, Dict, Any, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Adicione essa importação se estiver disponível no seu ambiente
# Se não estiver, você precisará instalar o pacote 'argon2-cffi'
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class CryptoUtils:
    """Classe para operações criptográficas."""
    
    SALT_SIZE = 16
    IV_SIZE = 16
    NONCE_SIZE = 12  # Para GCM e ChaCha20-Poly1305
    ITERATIONS = 100_000
    BLOCK_SIZE = 128  # Em bits
    
    # Valores padrão para Argon2id
    ARGON_MEMORY_COST = 65536     # 64 MB
    ARGON_TIME_COST = 3           # 3 iterações
    ARGON_PARALLELISM = 4         # 4 threads
    
    # Tipos de algoritmo
    ALG_AES_CBC = "aes-cbc"       # Original
    ALG_AES_GCM = "aes-gcm"       # Novo: AES-GCM
    ALG_CHACHA20 = "chacha20"     # Novo: ChaCha20-Poly1305
    
    # Tipos de KDF (Key Derivation Function)
    KDF_PBKDF2 = "pbkdf2"         # Original
    KDF_ARGON2ID = "argon2id"     # Novo: Argon2id
    KDF_SCRYPT = "scrypt"         # Alternativa: Scrypt
    
    # Valores padrão para parâmetros
    DEFAULT_ALGORITHM = ALG_AES_CBC
    DEFAULT_KDF = KDF_PBKDF2
    
    @staticmethod
    def generate_salt() -> bytes:
        """Gera um salt aleatório."""
        return os.urandom(CryptoUtils.SALT_SIZE)
    
    @staticmethod
    def generate_iv() -> bytes:
        """Gera um IV aleatório."""
        return os.urandom(CryptoUtils.IV_SIZE)
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Gera um nonce aleatório para GCM e ChaCha20-Poly1305."""
        return os.urandom(CryptoUtils.NONCE_SIZE)
    
    @staticmethod
    def derive_key(password: str, salt: bytes, kdf_type: str = DEFAULT_KDF, 
                   params: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Deriva uma chave a partir da senha usando o KDF especificado.
        
        Args:
            password: Senha usada para derivar a chave
            salt: Salt para a derivação
            kdf_type: Tipo de KDF (pbkdf2, argon2id, scrypt)
            params: Parâmetros específicos do KDF
        
        Returns:
            Chave derivada (32 bytes para AES-256)
        """
        if params is None:
            params = {}
        
        if kdf_type == CryptoUtils.KDF_PBKDF2:
            iterations = params.get('iterations', CryptoUtils.ITERATIONS)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 (32 bytes)
                salt=salt,
                iterations=iterations
            )
            return kdf.derive(password.encode('utf-8'))
        
        elif kdf_type == CryptoUtils.KDF_ARGON2ID:
            if not ARGON2_AVAILABLE:
                raise ImportError("Argon2id não está disponível. Instale o pacote 'argon2-cffi'")
            
            memory_cost = params.get('memory_cost', CryptoUtils.ARGON_MEMORY_COST)
            time_cost = params.get('time_cost', CryptoUtils.ARGON_TIME_COST)
            parallelism = params.get('parallelism', CryptoUtils.ARGON_PARALLELISM)
            
            # Configurar o PasswordHasher com os parâmetros fornecidos
            ph = PasswordHasher(
                memory_cost=memory_cost,
                time_cost=time_cost,
                parallelism=parallelism,
                hash_len=32,
                type=2  # Tipo 2 é Argon2id
            )
            
            # Derivar a chave - Argon2 precisa de uma senha em formato de string
            # e de um salt que seja parte do hash
            salt_str = base64.b64encode(salt).decode('ascii')
            hash_encoded = ph.hash(password + salt_str)
            
            # Extrair a chave derivada
            import hashlib
            key = hashlib.sha256((hash_encoded + password).encode()).digest()
            return key
        
        elif kdf_type == CryptoUtils.KDF_SCRYPT:
            memory_cost = params.get('memory_cost', 2**14)  # ~16MB
            n = params.get('n', 2**14)
            r = params.get('r', 8)
            p = params.get('p', 1)
            
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=n,
                r=r,
                p=p
            )
            return kdf.derive(password.encode('utf-8'))
        
        else:
            raise ValueError(f"Tipo de KDF não suportado: {kdf_type}")
    
    @staticmethod
    def encrypt_data(data: bytes, key: bytes, iv_or_nonce: bytes, 
                     algorithm: str = DEFAULT_ALGORITHM, 
                     associated_data: Optional[bytes] = None) -> bytes:
        """
        Criptografa dados usando o algoritmo especificado.
        
        Args:
            data: Dados a serem criptografados
            key: Chave de criptografia
            iv_or_nonce: IV (CBC) ou Nonce (GCM, ChaCha20)
            algorithm: Algoritmo de criptografia a ser usado
            associated_data: Dados associados para AEAD (opcional)
        
        Returns:
            Dados criptografados
        """
        if algorithm == CryptoUtils.ALG_AES_CBC:
            # Aplicar padding PKCS7
            padder = padding.PKCS7(CryptoUtils.BLOCK_SIZE).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Criptografar com AES-256-CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            return encrypted_data
        
        elif algorithm == CryptoUtils.ALG_AES_GCM:
            # AES-GCM não precisa de padding e já fornece autenticação
            aesgcm = AESGCM(key)
            ad = associated_data or b""
            encrypted_data = aesgcm.encrypt(iv_or_nonce, data, ad)
            return encrypted_data
        
        elif algorithm == CryptoUtils.ALG_CHACHA20:
            # ChaCha20-Poly1305 também fornece autenticação
            chacha = ChaCha20Poly1305(key)
            ad = associated_data or b""
            encrypted_data = chacha.encrypt(iv_or_nonce, data, ad)
            return encrypted_data
        
        else:
            raise ValueError(f"Algoritmo não suportado: {algorithm}")
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes, iv_or_nonce: bytes,
                     algorithm: str = DEFAULT_ALGORITHM,
                     associated_data: Optional[bytes] = None) -> bytes:
        """
        Descriptografa dados usando o algoritmo especificado.
        
        Args:
            encrypted_data: Dados criptografados
            key: Chave de descriptografia
            iv_or_nonce: IV (CBC) ou Nonce (GCM, ChaCha20)
            algorithm: Algoritmo usado na criptografia
            associated_data: Dados associados para AEAD (opcional)
        
        Returns:
            Dados descriptografados
        """
        if algorithm == CryptoUtils.ALG_AES_CBC:
            # Descriptografar com AES-256-CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remover padding PKCS7
            unpadder = padding.PKCS7(CryptoUtils.BLOCK_SIZE).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data
        
        elif algorithm == CryptoUtils.ALG_AES_GCM:
            # AES-GCM com autenticação embutida
            aesgcm = AESGCM(key)
            ad = associated_data or b""
            data = aesgcm.decrypt(iv_or_nonce, encrypted_data, ad)
            return data
        
        elif algorithm == CryptoUtils.ALG_CHACHA20:
            # ChaCha20-Poly1305 com autenticação embutida
            chacha = ChaCha20Poly1305(key)
            ad = associated_data or b""
            data = chacha.decrypt(iv_or_nonce, encrypted_data, ad)
            return data
        
        else:
            raise ValueError(f"Algoritmo não suportado: {algorithm}")
    
    @staticmethod
    def secure_overwrite(buffer: bytearray) -> None:
        """Sobrescreve um buffer de memória com zeros para remover dados sensíveis."""
        for i in range(len(buffer)):
            buffer[i] = 0
            
    # === Novos métodos para assinatura digital ===
    
    @staticmethod
    def generate_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Gera um par de chaves RSA para assinatura digital.
        
        Args:
            key_size: Tamanho da chave em bits
        
        Returns:
            Tupla contendo (chave privada, chave pública) em formato PEM
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Serializar as chaves para formato PEM
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_bytes, public_bytes
    
    @staticmethod
    def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
        """
        Assina dados usando a chave privada RSA.
        
        Args:
            data: Dados a serem assinados
            private_key_pem: Chave privada em formato PEM
            
        Returns:
            Assinatura digital
        """
        # Carregar a chave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )
        
        # Assinar os dados
        signature = private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
        """
        Verifica a assinatura digital de dados usando a chave pública RSA.
        
        Args:
            data: Dados que foram assinados
            signature: Assinatura digital
            public_key_pem: Chave pública em formato PEM
            
        Returns:
            True se a assinatura for válida, False caso contrário
        """
        # Carregar a chave pública
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        try:
            # Verificar a assinatura
            public_key.verify(
                signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False