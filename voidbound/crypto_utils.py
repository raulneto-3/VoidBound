import os
import secrets
import json
import base64
import struct
from typing import Tuple, Optional, Dict, Any, Union, List

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
    
    # Configurações existentes
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
    ALG_AES_CBC = "aes-cbc"
    ALG_AES_GCM = "aes-gcm"
    ALG_CHACHA20 = "chacha20"
    
    # Tipos de KDF (Key Derivation Function)
    KDF_PBKDF2 = "pbkdf2"
    KDF_ARGON2ID = "argon2id"
    KDF_SCRYPT = "scrypt"
    
    # Valores padrão para parâmetros
    DEFAULT_ALGORITHM = ALG_AES_CBC
    DEFAULT_KDF = KDF_PBKDF2
    
    # Novos parâmetros para criptografia híbrida
    RSA_KEY_SIZE = 2048
    CURVE_TYPE = ec.SECP384R1()  # Curva elíptica para ECDH
    COMPARTMENT_SIZE = 10 * 1024 * 1024  # 10MB por compartimento
    
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
        
    # ========== NOVOS MÉTODOS PARA RECURSOS AVANÇADOS ==========
    
    # === 1. CRIPTOGRAFIA DE CAMADA DUPLA ===
    
    @staticmethod
    def dual_layer_encrypt(data: bytes, password1: str, password2: str,
                         layer1_algorithm: str = ALG_AES_GCM,
                         layer2_algorithm: str = ALG_CHACHA20,
                         kdf_type: str = KDF_PBKDF2) -> Tuple[bytes, Dict[str, Any]]:
        """
        Aplica criptografia em duas camadas usando algoritmos diferentes.
        
        Args:
            data: Dados a serem criptografados
            password1: Senha para primeira camada
            password2: Senha para segunda camada  
            layer1_algorithm: Algoritmo para primeira camada
            layer2_algorithm: Algoritmo para segunda camada
            kdf_type: Tipo de KDF para derivação das chaves
            
        Returns:
            Tupla (dados duplamente criptografados, metadados)
        """
        # Primeira camada de criptografia
        salt1 = CryptoUtils.generate_salt()
        iv_nonce1 = CryptoUtils.generate_nonce() if layer1_algorithm != CryptoUtils.ALG_AES_CBC else CryptoUtils.generate_iv()
        key1 = CryptoUtils.derive_key(password1, salt1, kdf_type)
        
        # Criptografar os dados com a primeira chave
        first_layer = CryptoUtils.encrypt_data(data, key1, iv_nonce1, layer1_algorithm)
        
        # Segunda camada de criptografia
        salt2 = CryptoUtils.generate_salt()
        iv_nonce2 = CryptoUtils.generate_nonce() if layer2_algorithm != CryptoUtils.ALG_AES_CBC else CryptoUtils.generate_iv()
        key2 = CryptoUtils.derive_key(password2, salt2, kdf_type)
        
        # Criptografar o resultado da primeira camada com a segunda chave
        dual_encrypted = CryptoUtils.encrypt_data(first_layer, key2, iv_nonce2, layer2_algorithm)
        
        # Limpar chaves da memória
        key1_buffer = bytearray(key1)
        key2_buffer = bytearray(key2)
        CryptoUtils.secure_overwrite(key1_buffer)
        CryptoUtils.secure_overwrite(key2_buffer)
        
        # Preparar metadados
        metadata = {
            "dual_layer": True,
            "layer1_algorithm": layer1_algorithm,
            "layer2_algorithm": layer2_algorithm,
            "kdf_type": kdf_type,
            "salt1": base64.b64encode(salt1).decode('ascii'),
            "iv_nonce1": base64.b64encode(iv_nonce1).decode('ascii'),
            "salt2": base64.b64encode(salt2).decode('ascii'),
            "iv_nonce2": base64.b64encode(iv_nonce2).decode('ascii')
        }
        
        return dual_encrypted, metadata
    
    @staticmethod
    def dual_layer_decrypt(encrypted_data: bytes, password1: str, password2: str, metadata: Dict[str, Any]) -> bytes:
        """
        Descriptografa dados que foram criptografados em duas camadas.
        
        Args:
            encrypted_data: Dados duplamente criptografados
            password1: Senha para primeira camada
            password2: Senha para segunda camada
            metadata: Metadados contendo parâmetros de criptografia
            
        Returns:
            Dados descriptografados
        """
        # Extrair metadados
        layer1_algorithm = metadata.get("layer1_algorithm", CryptoUtils.ALG_AES_GCM)
        layer2_algorithm = metadata.get("layer2_algorithm", CryptoUtils.ALG_CHACHA20)
        kdf_type = metadata.get("kdf_type", CryptoUtils.KDF_PBKDF2)
        salt1 = base64.b64decode(metadata["salt1"])
        iv_nonce1 = base64.b64decode(metadata["iv_nonce1"])
        salt2 = base64.b64decode(metadata["salt2"])
        iv_nonce2 = base64.b64decode(metadata["iv_nonce2"])
        
        # Derivar chaves
        key2 = CryptoUtils.derive_key(password2, salt2, kdf_type)
        key1 = CryptoUtils.derive_key(password1, salt1, kdf_type)
        
        # Descriptografar segunda camada
        first_layer = CryptoUtils.decrypt_data(encrypted_data, key2, iv_nonce2, layer2_algorithm)
        
        # Descriptografar primeira camada
        decrypted_data = CryptoUtils.decrypt_data(first_layer, key1, iv_nonce1, layer1_algorithm)
        
        # Limpar chaves da memória
        key1_buffer = bytearray(key1)
        key2_buffer = bytearray(key2)
        CryptoUtils.secure_overwrite(key1_buffer)
        CryptoUtils.secure_overwrite(key2_buffer)
        
        return decrypted_data
    
    # === 2. CRIPTOGRAFIA HÍBRIDA ===
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE) -> Tuple[bytes, bytes]:
        """
        Gera um par de chaves RSA para criptografia híbrida.
        
        Args:
            key_size: Tamanho da chave em bits
            
        Returns:
            Tupla (chave privada, chave pública) em formato PEM
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
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
    def hybrid_encrypt(data: bytes, recipient_public_key_pem: bytes, 
                       algorithm: str = ALG_AES_GCM) -> Tuple[bytes, Dict[str, Any]]:
        """
        Aplica criptografia híbrida: simétrica para dados e assimétrica para a chave.
        
        Args:
            data: Dados a serem criptografados
            recipient_public_key_pem: Chave pública do destinatário em formato PEM
            algorithm: Algoritmo para criptografia simétrica
            
        Returns:
            Tupla (dados criptografados, metadados)
        """
        # Gerar uma chave simétrica aleatória
        symmetric_key = os.urandom(32)  # 256 bits
        
        # Gerar IV/nonce
        iv_or_nonce = CryptoUtils.generate_nonce() if algorithm != CryptoUtils.ALG_AES_CBC else CryptoUtils.generate_iv()
        
        # Criptografar os dados com a chave simétrica
        encrypted_data = CryptoUtils.encrypt_data(data, symmetric_key, iv_or_nonce, algorithm)
        
        # Carregar a chave pública do destinatário
        recipient_key = serialization.load_pem_public_key(recipient_public_key_pem)
        
        # Criptografar a chave simétrica com a chave pública do destinatário
        encrypted_key = recipient_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Limpar a chave simétrica da memória
        symmetric_key_buffer = bytearray(symmetric_key)
        CryptoUtils.secure_overwrite(symmetric_key_buffer)
        
        # Preparar metadados
        metadata = {
            "hybrid_encryption": True,
            "algorithm": algorithm,
            "iv_or_nonce": base64.b64encode(iv_or_nonce).decode('ascii'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('ascii'),
        }
        
        return encrypted_data, metadata
    
    @staticmethod
    def hybrid_decrypt(encrypted_data: bytes, private_key_pem: bytes, 
                       metadata: Dict[str, Any]) -> bytes:
        """
        Descriptografa dados usando criptografia híbrida.
        
        Args:
            encrypted_data: Dados criptografados
            private_key_pem: Chave privada do destinatário em formato PEM
            metadata: Metadados contendo parâmetros de criptografia
            
        Returns:
            Dados descriptografados
        """
        # Extrair metadados
        algorithm = metadata.get("algorithm", CryptoUtils.ALG_AES_GCM)
        iv_or_nonce = base64.b64decode(metadata["iv_or_nonce"])
        encrypted_key = base64.b64decode(metadata["encrypted_key"])
        
        # Carregar a chave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )
        
        # Descriptografar a chave simétrica
        symmetric_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Descriptografar os dados com a chave simétrica
        decrypted_data = CryptoUtils.decrypt_data(encrypted_data, symmetric_key, iv_or_nonce, algorithm)
        
        # Limpar a chave simétrica da memória
        symmetric_key_buffer = bytearray(symmetric_key)
        CryptoUtils.secure_overwrite(symmetric_key_buffer)
        
        return decrypted_data
        
    # === 3. MÉTODOS PARA COMPARTIMENTALIZAÇÃO ===
    
    @staticmethod
    def split_data(data: bytes, compartment_size: int = COMPARTMENT_SIZE) -> List[bytes]:
        """
        Divide os dados em compartimentos de tamanho fixo.
        
        Args:
            data: Dados a serem divididos
            compartment_size: Tamanho de cada compartimento em bytes
            
        Returns:
            Lista de compartimentos como bytes
        """
        if not data:
            return []
            
        compartments = []
        for i in range(0, len(data), compartment_size):
            compartment = data[i:i+compartment_size]
            compartments.append(compartment)
            
        return compartments
    
    @staticmethod
    def join_data(compartments: List[bytes]) -> bytes:
        """
        Junta os compartimentos em um único bloco de dados.
        
        Args:
            compartments: Lista de compartimentos como bytes
            
        Returns:
            Dados unidos como bytes
        """
        return b''.join(compartments)
    
    @staticmethod
    def encrypt_compartments(compartments: List[bytes], password: str, 
                           algorithm: str = ALG_AES_GCM,
                           kdf_type: str = KDF_PBKDF2) -> Tuple[List[bytes], Dict[str, Any]]:
        """
        Criptografa cada compartimento independentemente com chaves diferentes.
        
        Args:
            compartments: Lista de compartimentos a serem criptografados
            password: Senha base para derivação das chaves
            algorithm: Algoritmo de criptografia
            kdf_type: Tipo de KDF para derivação das chaves
            
        Returns:
            Tupla (compartimentos criptografados, metadados)
        """
        encrypted_compartments = []
        compartment_metadata = []
        
        # Derivar sal mestre da senha
        master_salt = CryptoUtils.generate_salt()
        master_key = CryptoUtils.derive_key(password, master_salt, kdf_type)
        
        for i, compartment in enumerate(compartments):
            # Derivar sal e IV/nonce únicos para cada compartimento usando o sal mestre
            compartment_salt_input = f"{i}-{base64.b64encode(master_salt).decode('ascii')}".encode()
            compartment_salt = CryptoUtils.hash_data(compartment_salt_input)[:16]  # 16 bytes para o sal
            compartment_iv_input = f"{i+1000}-{base64.b64encode(master_salt).decode('ascii')}".encode()
            
            if algorithm == CryptoUtils.ALG_AES_CBC:
                iv_or_nonce = CryptoUtils.hash_data(compartment_iv_input)[:16]  # 16 bytes para IV
            else:
                iv_or_nonce = CryptoUtils.hash_data(compartment_iv_input)[:12]  # 12 bytes para nonce
                
            # Derivar uma chave única para este compartimento
            key = CryptoUtils.derive_key(password, compartment_salt, kdf_type)
            
            # Criptografar o compartimento
            encrypted_compartment = CryptoUtils.encrypt_data(compartment, key, iv_or_nonce, algorithm)
            encrypted_compartments.append(encrypted_compartment)
            
            # Armazenar metadados para este compartimento
            compartment_metadata.append({
                "index": i,
                "salt": base64.b64encode(compartment_salt).decode('ascii'),
                "iv_or_nonce": base64.b64encode(iv_or_nonce).decode('ascii')
            })
            
            # Limpar a chave da memória
            key_buffer = bytearray(key)
            CryptoUtils.secure_overwrite(key_buffer)
        
        # Limpar a chave mestra da memória
        master_key_buffer = bytearray(master_key)
        CryptoUtils.secure_overwrite(master_key_buffer)
        
        # Preparar metadados globais
        metadata = {
            "compartmentalized": True,
            "algorithm": algorithm,
            "kdf_type": kdf_type,
            "master_salt": base64.b64encode(master_salt).decode('ascii'),
            "compartment_count": len(compartments),
            "compartment_metadata": compartment_metadata
        }
        
        return encrypted_compartments, metadata
    
    @staticmethod
    def decrypt_compartments(encrypted_compartments: List[bytes], password: str, 
                           metadata: Dict[str, Any]) -> List[bytes]:
        """
        Descriptografa compartimentos criptografados independentemente.
        
        Args:
            encrypted_compartments: Lista de compartimentos criptografados
            password: Senha usada para criptografia
            metadata: Metadados contendo parâmetros de criptografia
            
        Returns:
            Lista de compartimentos descriptografados
        """
        algorithm = metadata.get("algorithm", CryptoUtils.ALG_AES_GCM)
        kdf_type = metadata.get("kdf_type", CryptoUtils.KDF_PBKDF2)
        compartment_metadata = metadata["compartment_metadata"]
        
        decrypted_compartments = []
        
        for i, encrypted_compartment in enumerate(encrypted_compartments):
            # Obter metadados para este compartimento
            cm = compartment_metadata[i]
            compartment_salt = base64.b64decode(cm["salt"])
            iv_or_nonce = base64.b64decode(cm["iv_or_nonce"])
            
            # Derivar a chave para este compartimento
            key = CryptoUtils.derive_key(password, compartment_salt, kdf_type)
            
            # Descriptografar o compartimento
            decrypted_compartment = CryptoUtils.decrypt_data(
                encrypted_compartment, key, iv_or_nonce, algorithm
            )
            decrypted_compartments.append(decrypted_compartment)
            
            # Limpar a chave da memória
            key_buffer = bytearray(key)
            CryptoUtils.secure_overwrite(key_buffer)
        
        return decrypted_compartments
        
    @staticmethod
    def hash_data(data: bytes) -> bytes:
        """Calcula o hash SHA-256 dos dados."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()