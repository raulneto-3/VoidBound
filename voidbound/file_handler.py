import os
import shutil
import tempfile
import logging
import base64
from typing import List, Dict, Any, Optional, Tuple

from .crypto_utils import CryptoUtils
from .file_format import FileFormat


class FileHandler:
    """Manipulador de arquivos para operações de criptografia."""
    
    CHUNK_SIZE = 1024 * 1024  # 1MB
    
    @staticmethod
    def is_encrypted_file(filepath: str) -> bool:
        """Verifica se um arquivo tem a extensão de criptografia."""
        return filepath.endswith(FileHandler.ENCRYPTED_EXTENSION)
    
    @staticmethod
    def get_output_path(input_path: str, encrypt: bool, output_dir: Optional[str] = None) -> str:
        """
        Determina o caminho de saída com base na operação (criptografar/descriptografar).
        
        Args:
            input_path: Caminho do arquivo de entrada.
            encrypt: Se True, adiciona a extensão de criptografia; 
                     se False, remove a extensão.
            output_dir: Diretório de saída opcional.
            
        Returns:
            Caminho do arquivo de saída.
        """
        base_path = input_path
        
        if output_dir:
            base_name = os.path.basename(input_path)
            base_path = os.path.join(output_dir, base_name)
        
        if encrypt:
            return f"{base_path}{FileHandler.ENCRYPTED_EXTENSION}"
        else:
            # Remover extensão de criptografia
            if FileHandler.is_encrypted_file(base_path):
                return base_path[:-len(FileHandler.ENCRYPTED_EXTENSION)]
            return f"{base_path}.decrypted"  # Fallback se não tiver extensão correta
    
    @staticmethod
    def read_file_chunks(filepath: str) -> Generator[bytes, None, None]:
        """
        Lê um arquivo em chunks para processamento eficiente de memória.
        
        Args:
            filepath: Caminho do arquivo para ler.
            
        Yields:
            Chunks do conteúdo do arquivo.
        """
        with open(filepath, 'rb') as file:
            while True:
                chunk = file.read(FileHandler.CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk
    
    @staticmethod
    def encrypt_file(
        input_path: str, 
        password: str, 
        output_path: Optional[str] = None,
        verbose: bool = False,
        algorithm: str = CryptoUtils.DEFAULT_ALGORITHM,
        kdf_type: str = CryptoUtils.DEFAULT_KDF,
        kdf_params: Optional[Dict[str, Any]] = None,
        sign_with_key: Optional[bytes] = None,
        associated_data: Optional[bytes] = None
    ) -> str:
        """
        Criptografa um arquivo.
        
        Args:
            input_path: Caminho do arquivo a ser criptografado
            password: Senha para criptografia
            output_path: Caminho para salvar o arquivo criptografado (opcional)
            verbose: Se True, exibe mensagens detalhadas
            algorithm: Algoritmo de criptografia
            kdf_type: Tipo de derivação de chave
            kdf_params: Parâmetros adicionais para o KDF
            sign_with_key: Chave privada para assinar o arquivo (opcional)
            associated_data: Dados associados para AEAD (opcional)
            
        Returns:
            Caminho do arquivo criptografado
        """
        if verbose:
            logging.info(f"Criptografando arquivo {input_path}")
        
        # Gerar salt e iv/nonce
        salt = CryptoUtils.generate_salt()
        iv_or_nonce = None
        
        # Gerar IV ou Nonce adequado para o algoritmo
        if algorithm == CryptoUtils.ALG_AES_CBC:
            iv_or_nonce = CryptoUtils.generate_iv()
        else:
            iv_or_nonce = CryptoUtils.generate_nonce()
            
        # Derivar chave
        key = CryptoUtils.derive_key(password, salt, kdf_type, kdf_params)
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            output_path = input_path + ".encrypted"
        
        # Preparar metadados
        metadata = {
            "algorithm": algorithm,
            "kdf": kdf_type,
            "salt": base64.b64encode(salt).decode('ascii'),
            "iv_or_nonce": base64.b64encode(iv_or_nonce).decode('ascii')
        }
        
        # Adicionar parâmetros do KDF se fornecidos
        if kdf_params:
            metadata["kdf_params"] = kdf_params
            
        # Adicionar dados associados se fornecidos (para verificação)
        if associated_data:
            metadata["ad_hash"] = base64.b64encode(
                CryptoUtils.hash_data(associated_data)
            ).decode('ascii')
        
        try:
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Escrever o cabeçalho com metadados
                header = FileFormat.pack_header(metadata)
                outfile.write(header)
                
                # Se for assinar, preparar buffer para todo o conteúdo criptografado
                if sign_with_key:
                    encrypted_buffer = bytearray()
                
                # Processar o arquivo em chunks
                while True:
                    chunk = infile.read(FileHandler.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # Criptografar o chunk
                    encrypted_chunk = CryptoUtils.encrypt_data(
                        chunk, key, iv_or_nonce, algorithm, associated_data
                    )
                    
                    if sign_with_key:
                        encrypted_buffer.extend(encrypted_chunk)
                    else:
                        outfile.write(encrypted_chunk)
                
                # Se estiver assinando, assinar todos os dados criptografados e adicionar a assinatura
                if sign_with_key:
                    signature = CryptoUtils.sign_data(bytes(encrypted_buffer), sign_with_key)
                    
                    # Adicionar a assinatura ao final do arquivo
                    sig_metadata = {
                        "signature_size": len(signature),
                        "signature": base64.b64encode(signature).decode('ascii')
                    }
                    
                    # Escrever o conteúdo criptografado e a assinatura
                    outfile.write(encrypted_buffer)
                    outfile.write(FileFormat.pack_header(sig_metadata))
            
            if verbose:
                logging.info(f"Arquivo criptografado salvo como {output_path}")
            
            # Limpar a chave da memória
            key_buffer = bytearray(key)
            CryptoUtils.secure_overwrite(key_buffer)
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao criptografar arquivo: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_file(
        input_path: str, 
        password: str, 
        output_path: Optional[str] = None,
        verbose: bool = False,
        verify_with_key: Optional[bytes] = None,
        associated_data: Optional[bytes] = None
    ) -> str:
        """
        Descriptografa um arquivo.
        
        Args:
            input_path: Caminho do arquivo criptografado
            password: Senha para descriptografia
            output_path: Caminho para salvar o arquivo descriptografado (opcional)
            verbose: Se True, exibe mensagens detalhadas
            verify_with_key: Chave pública para verificar assinatura (opcional)
            associated_data: Dados associados para AEAD (opcional)
            
        Returns:
            Caminho do arquivo descriptografado
        """
        if verbose:
            logging.info(f"Descriptografando arquivo {input_path}")
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            # Remover extensão .encrypted se presente
            if input_path.endswith(".encrypted"):
                output_path = input_path[:-10]
            else:
                output_path = input_path + ".decrypted"
        
        try:
            with open(input_path, 'rb') as infile:
                # Ler os primeiros bytes para analisar o cabeçalho
                header_data = infile.read(8192)  # Ler o suficiente para o cabeçalho
                
                # Extrair metadados
                metadata, data_offset = FileFormat.unpack_header(header_data)
                
                # Mover o cursor do arquivo para o início dos dados criptografados
                infile.seek(data_offset)
                
                # Extrair parâmetros dos metadados
                algorithm = metadata.get("algorithm", CryptoUtils.DEFAULT_ALGORITHM)
                kdf_type = metadata.get("kdf", CryptoUtils.DEFAULT_KDF)
                salt = base64.b64decode(metadata["salt"])
                iv_or_nonce = base64.b64decode(metadata["iv_or_nonce"])
                kdf_params = metadata.get("kdf_params", None)
                
                # Verificar dados associados se fornecidos
                if associated_data and "ad_hash" in metadata:
                    expected_hash = base64.b64decode(metadata["ad_hash"])
                    actual_hash = CryptoUtils.hash_data(associated_data)
                    if actual_hash != expected_hash:
                        raise ValueError("Falha na verificação de dados associados")
                
                # Derivar chave
                key = CryptoUtils.derive_key(password, salt, kdf_type, kdf_params)
                
                # Se precisar verificar assinatura, ler arquivo inteiro
                signature = None
                encrypted_data = None
                
                if verify_with_key:
                    # Ler todo o conteúdo criptografado
                    encrypted_data = infile.read()
                    
                    # Verificar se há bloco de assinatura no final
                    try:
                        sig_metadata, _ = FileFormat.unpack_header(encrypted_data[-8192:])
                        signature = base64.b64decode(sig_metadata["signature"])
                        
                        # Remover a assinatura dos dados criptografados
                        sig_offset = len(encrypted_data) - sig_metadata["signature_size"]
                        encrypted_data = encrypted_data[:sig_offset]
                    except Exception:
                        # Se não houver assinatura, continuar sem verificação
                        if verbose:
                            logging.warning("Assinatura não encontrada, continuando sem verificação")
                
                # Abrir arquivo de saída
                with open(output_path, 'wb') as outfile:
                    if verify_with_key and signature and encrypted_data:
                        # Verificar assinatura
                        if not CryptoUtils.verify_signature(encrypted_data, signature, verify_with_key):
                            raise ValueError("Assinatura digital inválida")
                        
                        # Descriptografar dados em chunks
                        offset = 0
                        while offset < len(encrypted_data):
                            chunk_size = min(FileHandler.CHUNK_SIZE, len(encrypted_data) - offset)
                            chunk = encrypted_data[offset:offset+chunk_size]
                            
                            # Descriptografar o chunk
                            decrypted_chunk = CryptoUtils.decrypt_data(
                                chunk, key, iv_or_nonce, algorithm, associated_data
                            )
                            outfile.write(decrypted_chunk)
                            offset += chunk_size
                    else:
                        # Processar o arquivo em chunks (sem verificação de assinatura)
                        while True:
                            chunk = infile.read(FileHandler.CHUNK_SIZE)
                            if not chunk:
                                break
                            
                            # Descriptografar o chunk
                            decrypted_chunk = CryptoUtils.decrypt_data(
                                chunk, key, iv_or_nonce, algorithm, associated_data
                            )
                            outfile.write(decrypted_chunk)
                
            if verbose:
                logging.info(f"Arquivo descriptografado salvo como {output_path}")
            
            # Limpar a chave da memória
            key_buffer = bytearray(key)
            CryptoUtils.secure_overwrite(key_buffer)
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao descriptografar arquivo: {str(e)}")
            raise
    
    @staticmethod
    def process_path(input_path: str, password: str, encrypt: bool, 
                    output_dir: Optional[str] = None, verbose: bool = False) -> List[str]:
        """
        Processa um caminho (arquivo ou diretório) para criptografia/descriptografia.
        
        Args:
            input_path: Caminho de entrada (arquivo ou diretório).
            password: Senha para criptografia/descriptografia.
            encrypt: Se True, criptografa; se False, descriptografa.
            output_dir: Diretório de saída opcional.
            verbose: Se True, exibe informações detalhadas.
            
        Returns:
            Lista dos caminhos de arquivos processados.
        """
        # Remover barras finais do caminho de entrada para garantir consistência
        input_path = input_path.rstrip('\\/')
        
        processed_files = []
        
        if os.path.isfile(input_path):
            # Processar arquivo único
            if encrypt:
                output_path = FileHandler.get_output_path(input_path, True, output_dir)
                processed_files.append(FileHandler.encrypt_file(input_path, password, output_path, verbose))
            else:
                if FileHandler.is_encrypted_file(input_path):
                    output_path = FileHandler.get_output_path(input_path, False, output_dir)
                    processed_files.append(FileHandler.decrypt_file(input_path, password, output_path, verbose))
                else:
                    if verbose:
                        print(f"Ignorando arquivo não criptografado: {input_path}")
        
        elif os.path.isdir(input_path):
            # Processar diretório recursivamente
            for root, _, files in os.walk(input_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Determinar diretório de saída relativo
                    if output_dir:
                        rel_path = os.path.relpath(root, input_path)
                        current_output_dir = os.path.join(output_dir, rel_path)
                        os.makedirs(current_output_dir, exist_ok=True)
                    else:
                        current_output_dir = None
                    
                    # Processar cada arquivo
                    if encrypt:
                        if not FileHandler.is_encrypted_file(file_path):
                            output_path = FileHandler.get_output_path(file_path, True, current_output_dir)
                            processed_files.append(FileHandler.encrypt_file(file_path, password, output_path, verbose))
                    else:
                        if FileHandler.is_encrypted_file(file_path):
                            output_path = FileHandler.get_output_path(file_path, False, current_output_dir)
                            processed_files.append(FileHandler.decrypt_file(file_path, password, output_path, verbose))
        
        else:
            raise FileNotFoundError(f"O caminho não existe: {input_path}")
        
        return processed_files
    
    @staticmethod
    def archive_directory(input_dir: str, output_path: Optional[str] = None) -> str:
        """
        Empacota um diretório inteiro em um único arquivo tar.
        
        Args:
            input_dir: Caminho do diretório a ser empacotado
            output_path: Caminho de saída opcional para o arquivo tar
            
        Returns:
            Caminho do arquivo tar criado
        """
        input_dir = input_dir.rstrip('\\/')
        if not os.path.isdir(input_dir):
            raise ValueError(f"O caminho não é um diretório: {input_dir}")
        
        dir_name = os.path.basename(input_dir)
        
        if not output_path:
            # Criar arquivo temporário se nenhum caminho de saída for fornecido
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.tar')
            output_path = temp_file.name
            temp_file.close()
        
        with tarfile.open(output_path, "w") as tar:
            tar.add(input_dir, arcname=dir_name)
            
        return output_path

    @staticmethod
    def extract_archive(archive_path: str, output_dir: str) -> str:
        """
        Extrai um arquivo tar em um diretório.
        
        Args:
            archive_path: Caminho do arquivo tar
            output_dir: Diretório onde extrair o conteúdo
            
        Returns:
            Caminho do diretório onde o conteúdo foi extraído
        """
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"O arquivo não existe: {archive_path}")
        
        with tarfile.open(archive_path, "r") as tar:
            tar.extractall(path=output_dir)
        
        return output_dir

    @staticmethod
    def hash_data(data: bytes) -> bytes:
        """Calcula o hash SHA-256 dos dados."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    # === MÉTODOS PARA CRIPTOGRAFIA DE CAMADA DUPLA ===
    
    @staticmethod
    def dual_layer_encrypt_file(
        input_path: str,
        password1: str,
        password2: str,
        output_path: Optional[str] = None,
        verbose: bool = False,
        layer1_algorithm: str = CryptoUtils.ALG_AES_GCM,
        layer2_algorithm: str = CryptoUtils.ALG_CHACHA20,
        kdf_type: str = CryptoUtils.KDF_PBKDF2
    ) -> str:
        """
        Criptografa um arquivo usando criptografia de camada dupla.
        
        Args:
            input_path: Caminho do arquivo a ser criptografado
            password1: Senha para primeira camada
            password2: Senha para segunda camada
            output_path: Caminho para salvar o arquivo criptografado (opcional)
            verbose: Se True, exibe informações detalhadas
            layer1_algorithm: Algoritmo para primeira camada
            layer2_algorithm: Algoritmo para segunda camada
            kdf_type: Tipo de KDF para derivação das chaves
            
        Returns:
            Caminho do arquivo criptografado
        """
        if verbose:
            logging.info(f"Criptografando arquivo {input_path} com proteção de camada dupla")
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            output_path = input_path + ".dual-encrypted"
        
        try:
            # Ler arquivo de entrada
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Aplicar criptografia de camada dupla
            encrypted_data, metadata = CryptoUtils.dual_layer_encrypt(
                data, password1, password2, layer1_algorithm, layer2_algorithm, kdf_type
            )
            
            # Salvar arquivo criptografado
            with open(output_path, 'wb') as f:
                header = FileFormat.pack_header(metadata)
                f.write(header)
                f.write(encrypted_data)
            
            if verbose:
                logging.info(f"Arquivo criptografado salvo como {output_path}")
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao criptografar arquivo com dupla camada: {str(e)}")
            raise
    
    @staticmethod
    def dual_layer_decrypt_file(
        input_path: str,
        password1: str,
        password2: str,
        output_path: Optional[str] = None,
        verbose: bool = False
    ) -> str:
        """
        Descriptografa um arquivo que foi criptografado com camada dupla.
        
        Args:
            input_path: Caminho do arquivo criptografado
            password1: Senha para primeira camada
            password2: Senha para segunda camada
            output_path: Caminho para salvar o arquivo descriptografado (opcional)
            verbose: Se True, exibe informações detalhadas
            
        Returns:
            Caminho do arquivo descriptografado
        """
        if verbose:
            logging.info(f"Descriptografando arquivo {input_path} com proteção de camada dupla")
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            if input_path.endswith(".dual-encrypted"):
                output_path = input_path[:-14]
            else:
                output_path = input_path + ".decrypted"
        
        try:
            # Ler arquivo criptografado
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Extrair metadados
            metadata, data_offset = FileFormat.unpack_header(data)
            encrypted_data = data[data_offset:]
            
            # Verificar se é um arquivo de camada dupla
            if not metadata.get("dual_layer", False):
                raise ValueError("O arquivo não está criptografado com proteção de camada dupla")
            
            # Aplicar descriptografia de camada dupla
            decrypted_data = CryptoUtils.dual_layer_decrypt(
                encrypted_data, password1, password2, metadata
            )
            
            # Salvar arquivo descriptografado
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            if verbose:
                logging.info(f"Arquivo descriptografado salvo como {output_path}")
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao descriptografar arquivo com dupla camada: {str(e)}")
            raise
    
    # === MÉTODOS PARA CRIPTOGRAFIA HÍBRIDA ===
    
    @staticmethod
    def hybrid_encrypt_file(
        input_path: str,
        recipient_public_key_path: str,
        output_path: Optional[str] = None,
        verbose: bool = False,
        algorithm: str = CryptoUtils.ALG_AES_GCM
    ) -> str:
        """
        Criptografa um arquivo usando criptografia híbrida.
        
        Args:
            input_path: Caminho do arquivo a ser criptografado
            recipient_public_key_path: Caminho da chave pública do destinatário
            output_path: Caminho para salvar o arquivo criptografado (opcional)
            verbose: Se True, exibe informações detalhadas
            algorithm: Algoritmo para criptografia simétrica
            
        Returns:
            Caminho do arquivo criptografado
        """
        if verbose:
            logging.info(f"Criptografando arquivo {input_path} com criptografia híbrida")
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            output_path = input_path + ".hybrid-encrypted"
        
        try:
            # Ler arquivo de entrada
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Ler chave pública do destinatário
            with open(recipient_public_key_path, 'rb') as f:
                public_key_pem = f.read()
            
            # Aplicar criptografia híbrida
            encrypted_data, metadata = CryptoUtils.hybrid_encrypt(
                data, public_key_pem, algorithm
            )
            
            # Salvar arquivo criptografado
            with open(output_path, 'wb') as f:
                header = FileFormat.pack_header(metadata)
                f.write(header)
                f.write(encrypted_data)
            
            if verbose:
                logging.info(f"Arquivo criptografado salvo como {output_path}")
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao criptografar arquivo com criptografia híbrida: {str(e)}")
            raise
    
    @staticmethod
    def hybrid_decrypt_file(
        input_path: str,
        private_key_path: str,
        output_path: Optional[str] = None,
        verbose: bool = False
    ) -> str:
        """
        Descriptografa um arquivo que foi criptografado com criptografia híbrida.
        
        Args:
            input_path: Caminho do arquivo criptografado
            private_key_path: Caminho da chave privada
            output_path: Caminho para salvar o arquivo descriptografado (opcional)
            verbose: Se True, exibe informações detalhadas
            
        Returns:
            Caminho do arquivo descriptografado
        """
        if verbose:
            logging.info(f"Descriptografando arquivo {input_path} com criptografia híbrida")
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            if input_path.endswith(".hybrid-encrypted"):
                output_path = input_path[:-17]
            else:
                output_path = input_path + ".decrypted"
        
        try:
            # Ler arquivo criptografado
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Extrair metadados
            metadata, data_offset = FileFormat.unpack_header(data)
            encrypted_data = data[data_offset:]
            
            # Verificar se é um arquivo de criptografia híbrida
            if not metadata.get("hybrid_encryption", False):
                raise ValueError("O arquivo não está criptografado com criptografia híbrida")
            
            # Ler chave privada
            with open(private_key_path, 'rb') as f:
                private_key_pem = f.read()
            
            # Aplicar descriptografia híbrida
            decrypted_data = CryptoUtils.hybrid_decrypt(
                encrypted_data, private_key_pem, metadata
            )
            
            # Salvar arquivo descriptografado
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            if verbose:
                logging.info(f"Arquivo descriptografado salvo como {output_path}")
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao descriptografar arquivo com criptografia híbrida: {str(e)}")
            raise
    
    # === MÉTODOS PARA COMPARTIMENTALIZAÇÃO ===
    
    @staticmethod
    def compartmentalized_encrypt_file(
        input_path: str,
        password: str,
        output_path: Optional[str] = None,
        verbose: bool = False,
        algorithm: str = CryptoUtils.ALG_AES_GCM,
        kdf_type: str = CryptoUtils.KDF_PBKDF2,
        compartment_size: int = CryptoUtils.COMPARTMENT_SIZE
    ) -> str:
        """
        Criptografa um arquivo usando compartimentalização.
        
        Args:
            input_path: Caminho do arquivo a ser criptografado
            password: Senha para criptografia
            output_path: Caminho para salvar o arquivo criptografado (opcional)
            verbose: Se True, exibe informações detalhadas
            algorithm: Algoritmo para criptografia
            kdf_type: Tipo de KDF para derivação das chaves
            compartment_size: Tamanho de cada compartimento em bytes
            
        Returns:
            Caminho do arquivo criptografado
        """
        if verbose:
            logging.info(f"Criptografando arquivo {input_path} com compartimentalização")
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            output_path = input_path + ".comp-encrypted"
        
        try:
            # Ler arquivo de entrada em blocos
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Dividir dados em compartimentos
            compartments = CryptoUtils.split_data(data, compartment_size)
            
            if verbose:
                logging.info(f"Arquivo dividido em {len(compartments)} compartimentos")
            
            # Criptografar cada compartimento independentemente
            encrypted_compartments, metadata = CryptoUtils.encrypt_compartments(
                compartments, password, algorithm, kdf_type
            )
            
            # Empacotar compartimentos criptografados
            packed_data = FileFormat.pack_compartments(encrypted_compartments, metadata)
            
            # Salvar arquivo criptografado
            with open(output_path, 'wb') as f:
                f.write(packed_data)
            
            if verbose:
                logging.info(f"Arquivo criptografado salvo como {output_path}")
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao criptografar arquivo com compartimentalização: {str(e)}")
            raise
    
    @staticmethod
    def compartmentalized_decrypt_file(
        input_path: str,
        password: str,
        output_path: Optional[str] = None,
        verbose: bool = False
    ) -> str:
        """
        Descriptografa um arquivo que foi criptografado com compartimentalização.
        
        Args:
            input_path: Caminho do arquivo criptografado
            password: Senha para descriptografia
            output_path: Caminho para salvar o arquivo descriptografado (opcional)
            verbose: Se True, exibe informações detalhadas
            
        Returns:
            Caminho do arquivo descriptografado
        """
        if verbose:
            logging.info(f"Descriptografando arquivo {input_path} com compartimentalização")
        
        # Definir caminho de saída se não fornecido
        if output_path is None:
            if input_path.endswith(".comp-encrypted"):
                output_path = input_path[:-15]
            else:
                output_path = input_path + ".decrypted"
        
        try:
            # Ler arquivo criptografado
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Desempacotar compartimentos criptografados
            encrypted_compartments, metadata = FileFormat.unpack_compartments(data)
            
            if verbose:
                logging.info(f"Arquivo contém {len(encrypted_compartments)} compartimentos criptografados")
            
            # Verificar se é um arquivo compartimentado
            if not metadata.get("compartmentalized", False):
                raise ValueError("O arquivo não está criptografado com compartimentalização")
            
            # Descriptografar cada compartimento independentemente
            decrypted_compartments = CryptoUtils.decrypt_compartments(
                encrypted_compartments, password, metadata
            )
            
            # Unir compartimentos descriptografados
            decrypted_data = CryptoUtils.join_data(decrypted_compartments)
            
            # Salvar arquivo descriptografado
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            if verbose:
                logging.info(f"Arquivo descriptografado salvo como {output_path}")
            
            return output_path
            
        except Exception as e:
            if verbose:
                logging.exception(f"Erro ao descriptografar arquivo com compartimentalização: {str(e)}")
            raise