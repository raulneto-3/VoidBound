import os
import pytest
import tempfile
import shutil
import subprocess
import sys
from pathlib import Path

# Caminho para o script principal
SCRIPT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cryptoservice.py'))


@pytest.fixture
def temp_dir():
    """Fixture para criar um diretório temporário."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def test_files(temp_dir):
    """Fixture para criar arquivos de teste de diferentes tamanhos."""
    files = {}
    
    # Arquivo pequeno (1 KB)
    small_file = os.path.join(temp_dir, "small.txt")
    with open(small_file, "wb") as f:
        f.write(os.urandom(1024))  # 1 KB de dados aleatórios
    files["small"] = small_file
    
    # Arquivo médio (1 MB)
    medium_file = os.path.join(temp_dir, "medium.bin")
    with open(medium_file, "wb") as f:
        f.write(os.urandom(1024 * 1024))  # 1 MB de dados aleatórios
    files["medium"] = medium_file
    
    # Criar estrutura de diretórios
    subdir = os.path.join(temp_dir, "subdir")
    os.makedirs(subdir)
    
    # Arquivo em subdiretório
    nested_file = os.path.join(subdir, "nested.txt")
    with open(nested_file, "wb") as f:
        f.write(b"Arquivo em subdiretorio")
    files["nested"] = nested_file
    
    return files


def test_encrypt_decrypt_file(temp_dir, test_files):
    """Teste de integração do fluxo completo de criptografia/descriptografia."""
    password = "senha_secreta"
    output_dir = os.path.join(temp_dir, "output")
    os.makedirs(output_dir)
    
    # Comando de criptografia
    encrypt_cmd = [
        sys.executable, SCRIPT_PATH,
        "--encrypt",
        "--input", test_files["small"],
        "--password", password,
        "--output", output_dir,
        "--verbose"
    ]
    
    # Executar comando de criptografia
    encrypt_result = subprocess.run(encrypt_cmd, capture_output=True, text=True)
    assert encrypt_result.returncode == 0, f"Falha na criptografia: {encrypt_result.stderr}"
    
    # Verificar se o arquivo criptografado foi criado
    encrypted_file = os.path.join(output_dir, os.path.basename(test_files["small"]) + ".encrypted")
    assert os.path.exists(encrypted_file)
    
    # Diretório para arquivo descriptografado
    decrypt_output = os.path.join(temp_dir, "decrypted")
    os.makedirs(decrypt_output)
    
    # Comando de descriptografia
    decrypt_cmd = [
        sys.executable, SCRIPT_PATH,
        "--decrypt",
        "--input", encrypted_file,
        "--password", password,
        "--output", decrypt_output,
        "--verbose"
    ]
    
    # Executar comando de descriptografia
    decrypt_result = subprocess.run(decrypt_cmd, capture_output=True, text=True)
    assert decrypt_result.returncode == 0, f"Falha na descriptografia: {decrypt_result.stderr}"
    
    # Verificar se o arquivo descriptografado foi criado
    decrypted_file = os.path.join(decrypt_output, os.path.basename(test_files["small"]))
    assert os.path.exists(decrypted_file)
    
    # Verificar se o conteúdo é o mesmo
    with open(test_files["small"], "rb") as f:
        original_content = f.read()
    with open(decrypted_file, "rb") as f:
        decrypted_content = f.read()
    
    assert original_content == decrypted_content


def test_encrypt_decrypt_directory(temp_dir, test_files):
    """Teste de integração para criptografia/descriptografia de diretório."""
    password = "senha_diretorio"  # Definindo uma senha única e consistente
    output_dir = os.path.join(temp_dir, "output_dir")
    os.makedirs(output_dir)
    
    # Comando de criptografia para o diretório
    encrypt_cmd = [
        sys.executable, SCRIPT_PATH,
        "--encrypt",
        "--input", temp_dir,
        "--password", password,
        "--output", output_dir,
        "--verbose"  # Adicionado para ajudar no diagnóstico
    ]
    
    # Executar comando de criptografia
    encrypt_result = subprocess.run(encrypt_cmd, capture_output=True, text=True)
    assert encrypt_result.returncode == 0, f"Falha na criptografia: {encrypt_result.stderr}"
    
    # Verificar se os arquivos criptografados foram criados
    for file_key in test_files:
        rel_path = os.path.relpath(test_files[file_key], temp_dir)
        encrypted_path = os.path.join(output_dir, rel_path + ".encrypted")
        assert os.path.exists(encrypted_path), f"Arquivo criptografado não encontrado: {encrypted_path}"
    
    # Diretório para arquivos descriptografados
    decrypt_output = os.path.join(temp_dir, "decrypted_dir")
    os.makedirs(decrypt_output)
    
    # Comando de descriptografia para o diretório
    decrypt_cmd = [
        sys.executable, SCRIPT_PATH,
        "--decrypt",
        "--input", output_dir,
        "--password", password,  # Usando a mesma senha definida acima
        "--output", decrypt_output,
        "--verbose"  # Adicionado para ajudar no diagnóstico
    ]
    
    # Executar comando de descriptografia
    decrypt_result = subprocess.run(decrypt_cmd, capture_output=True, text=True)
    assert decrypt_result.returncode == 0, f"Falha na descriptografia: {decrypt_result.stderr}"
    
    # Verificar se os arquivos descriptografados foram criados
    for file_key in test_files:
        rel_path = os.path.relpath(test_files[file_key], temp_dir)
        decrypted_path = os.path.join(decrypt_output, rel_path)
        assert os.path.exists(decrypted_path), f"Arquivo descriptografado não encontrado: {decrypted_path}"


def test_wrong_password(temp_dir, test_files):
    """Teste de integração com senha incorreta."""
    correct_password = "senha_correta"
    wrong_password = "senha_incorreta"
    
    # Criptografar com senha correta
    encrypt_cmd = [
        sys.executable, SCRIPT_PATH,
        "--encrypt",
        "--input", test_files["small"],
        "--password", correct_password
    ]
    encrypt_result = subprocess.run(encrypt_cmd, capture_output=True, text=True)
    assert encrypt_result.returncode == 0
    
    encrypted_file = test_files["small"] + ".encrypted"
    assert os.path.exists(encrypted_file)
    
    # Tentar descriptografar com senha incorreta
    decrypt_cmd = [
        sys.executable, SCRIPT_PATH,
        "--decrypt",
        "--input", encrypted_file,
        "--password", wrong_password
    ]
    decrypt_result = subprocess.run(decrypt_cmd, capture_output=True, text=True)
    
    # Deve falhar com erro
    assert decrypt_result.returncode == 1
    assert "Senha incorreta ou arquivo corrompido" in decrypt_result.stderr