import os
import shutil
from typing import Tuple, List, Optional, Generator
from pathlib import Path
import tarfile
import tempfile
from .crypto_utils import CryptoUtils


class FileHandler:
    """Classe para lidar com operações de arquivo."""
    
    ENCRYPTED_EXTENSION = ".encrypted"
    CHUNK_SIZE = 64 * 1024  # 64 KB
    
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
    def encrypt_file(input_path: str, password: str, output_path: Optional[str] = None,
                    verbose: bool = False) -> str:
        """
        Criptografa um arquivo usando AES-256-CBC.
        
        Args:
            input_path: Caminho do arquivo a ser criptografado.
            password: Senha para criptografia.
            output_path: Caminho de saída opcional para o arquivo criptografado.
            verbose: Se True, exibe informações detalhadas.
            
        Returns:
            Caminho do arquivo criptografado.
        """
        if not output_path:
            output_path = FileHandler.get_output_path(input_path, True)
        
        # Gerar salt e IV
        salt = CryptoUtils.generate_salt()
        iv = CryptoUtils.generate_iv()
        key = CryptoUtils.derive_key(password, salt)
        
        try:
            with open(output_path, 'wb') as out_file:
                # Escrever salt e IV no início do arquivo
                out_file.write(salt)
                out_file.write(iv)
                
                # Processar o arquivo em chunks
                for chunk in FileHandler.read_file_chunks(input_path):
                    encrypted_chunk = CryptoUtils.encrypt_data(chunk, key, iv)
                    out_file.write(encrypted_chunk)
            
            # Preservar metadados (opcional)
            shutil.copystat(input_path, output_path)
            
            if verbose:
                print(f"Arquivo criptografado salvo em: {output_path}")
            
            return output_path
        finally:
            # Limpar dados sensíveis da memória
            if 'key' in locals():
                CryptoUtils.secure_overwrite(bytearray(key))
    
    @staticmethod
    def decrypt_file(input_path: str, password: str, output_path: Optional[str] = None,
                     verbose: bool = False) -> str:
        """
        Descriptografa um arquivo criptografado com AES-256-CBC.
        
        Args:
            input_path: Caminho do arquivo criptografado.
            password: Senha para descriptografia.
            output_path: Caminho de saída opcional para o arquivo descriptografado.
            verbose: Se True, exibe informações detalhadas.
            
        Returns:
            Caminho do arquivo descriptografado.
        """
        if not output_path:
            output_path = FileHandler.get_output_path(input_path, False)
        
        try:
            with open(input_path, 'rb') as in_file:
                # Ler salt e IV do início do arquivo
                salt = in_file.read(CryptoUtils.SALT_SIZE)
                iv = in_file.read(CryptoUtils.IV_SIZE)
                
                if len(salt) != CryptoUtils.SALT_SIZE or len(iv) != CryptoUtils.IV_SIZE:
                    raise ValueError("Arquivo corrompido ou não criptografado corretamente")
                
                # Derivar chave da senha
                key = CryptoUtils.derive_key(password, salt)
                
                with open(output_path, 'wb') as out_file:
                    # Ler o primeiro chunk para validar a senha
                    first_chunk = in_file.read(FileHandler.CHUNK_SIZE)
                    if not first_chunk:
                        return output_path  # Arquivo vazio
                    
                    try:
                        decrypted_chunk = CryptoUtils.decrypt_data(first_chunk, key, iv)
                        out_file.write(decrypted_chunk)
                    except Exception as e:
                        # Limpar arquivo parcial de saída
                        out_file.close()
                        os.unlink(output_path)
                        raise ValueError("Senha incorreta ou arquivo corrompido") from e
                    
                    # Processar o resto do arquivo
                    while True:
                        chunk = in_file.read(FileHandler.CHUNK_SIZE)
                        if not chunk:
                            break
                        decrypted_chunk = CryptoUtils.decrypt_data(chunk, key, iv)
                        out_file.write(decrypted_chunk)
            
            # Preservar metadados (opcional)
            shutil.copystat(input_path, output_path)
            
            if verbose:
                print(f"Arquivo descriptografado salvo em: {output_path}")
            
            return output_path
        finally:
            # Limpar dados sensíveis da memória
            if 'key' in locals():
                CryptoUtils.secure_overwrite(bytearray(key))
        
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