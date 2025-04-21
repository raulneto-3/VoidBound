import os
import pytest
import tempfile
import shutil
from pathlib import Path

from vaultcodex.file_handler import FileHandler
from vaultcodex.crypto_utils import CryptoUtils


@pytest.fixture
def temp_dir():
    """Fixture para criar um diretório temporário."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def test_file(temp_dir):
    """Fixture para criar um arquivo de teste."""
    file_path = os.path.join(temp_dir, "test_file.txt")
    with open(file_path, "wb") as f:
        f.write(b"Conteudo de teste para criptografia")
    return file_path


class TestFileHandler:
    
    def test_is_encrypted_file(self):
        """Teste de verificação de arquivo criptografado."""
        assert FileHandler.is_encrypted_file("test_file.txt.encrypted") == True
        assert FileHandler.is_encrypted_file("test_file.txt") == False
    
    def test_get_output_path_encrypt(self):
        """Teste de geração de caminho de saída para criptografia."""
        input_path = os.path.join("tests", "files", "test_file.txt")
        output_path = FileHandler.get_output_path(input_path, encrypt=True)
        assert output_path == f"{input_path}{FileHandler.ENCRYPTED_EXTENSION}"
        
        # Com diretório de saída
        output_dir = os.path.join("tests", "files")
        output_path = FileHandler.get_output_path(input_path, encrypt=True, output_dir=output_dir)
        expected_path = os.path.join(output_dir, f"test_file.txt{FileHandler.ENCRYPTED_EXTENSION}")
        assert output_path == expected_path
        
    def test_get_output_path_decrypt(self):
        """Teste de geração de caminho de saída para descriptografia."""
        input_path = os.path.join("tests", "files", f"test_file.txt{FileHandler.ENCRYPTED_EXTENSION}")
        output_path = FileHandler.get_output_path(input_path, encrypt=False)
        expected_path = os.path.join("tests", "files", "test_file.txt")
        assert output_path == expected_path
        
        # Com diretório de saída
        output_dir = os.path.join("tests", "files")
        output_path = FileHandler.get_output_path(input_path, encrypt=False, output_dir=output_dir)
        expected_path = os.path.join(output_dir, "test_file.txt")
        assert output_path == expected_path
        
        # Arquivo sem extensão de criptografia
        input_path = os.path.join("tests", "files", "test_file.txt")
        output_path = FileHandler.get_output_path(input_path, encrypt=False)
        assert output_path == f"{input_path}.decrypted"

    def test_read_file_chunks(self, test_file):
        """Teste de leitura de arquivo em chunks."""
        chunks = list(FileHandler.read_file_chunks(test_file))
        
        # Reconstruir o conteúdo do arquivo
        content = b''.join(chunks)
        
        # Verificar se o conteúdo é o mesmo
        with open(test_file, "rb") as f:
            expected_content = f.read()
        
        assert content == expected_content
    
    def test_encrypt_decrypt_file(self, temp_dir, test_file):
        """Teste do ciclo completo de criptografia/descriptografia de arquivo."""
        password = "senha_teste"
        
        # Criptografar arquivo
        encrypted_path = FileHandler.encrypt_file(test_file, password, verbose=True)
        assert os.path.exists(encrypted_path)
        assert FileHandler.is_encrypted_file(encrypted_path)
        
        # Descriptografar arquivo
        decrypted_path = FileHandler.decrypt_file(encrypted_path, password, verbose=True)
        assert os.path.exists(decrypted_path)
        
        # Verificar se o conteúdo é o mesmo
        with open(test_file, "rb") as f:
            original_content = f.read()
        with open(decrypted_path, "rb") as f:
            decrypted_content = f.read()
        
        assert original_content == decrypted_content
    
    def test_wrong_password_decrypt(self, temp_dir, test_file):
        """Teste de descriptografia com senha incorreta."""
        correct_password = "senha_correta"
        wrong_password = "senha_incorreta"
        
        # Criptografar com senha correta
        encrypted_path = FileHandler.encrypt_file(test_file, correct_password)
        
        # Descriptografar com senha incorreta deve falhar
        with pytest.raises(ValueError, match="Senha incorreta ou arquivo corrompido"):
            FileHandler.decrypt_file(encrypted_path, wrong_password)
    
    def test_process_directory(self, temp_dir):
        """Teste de processamento recursivo de diretórios."""
        # Criar estrutura de diretórios e arquivos
        subdir = os.path.join(temp_dir, "subdir")
        os.makedirs(subdir)
        
        file1 = os.path.join(temp_dir, "file1.txt")
        file2 = os.path.join(subdir, "file2.txt")
        
        with open(file1, "wb") as f:
            f.write(b"Conteudo do arquivo 1")
        with open(file2, "wb") as f:
            f.write(b"Conteudo do arquivo 2")
        
        password = "senha_teste"
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        # Processar diretório (criptografar)
        processed_files = FileHandler.process_path(temp_dir, password, encrypt=True, output_dir=output_dir, verbose=True)
        
        # Verificar se os arquivos foram criptografados
        assert len(processed_files) == 2
        assert all(FileHandler.is_encrypted_file(f) for f in processed_files)
        
        # Processar diretório (descriptografar)
        decrypted_files = FileHandler.process_path(output_dir, password, encrypt=False, verbose=True)
        
        # Verificar se os arquivos foram descriptografados
        assert len(decrypted_files) == 2