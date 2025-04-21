import pytest
from vaultcodex.crypto_utils import CryptoUtils


class TestCryptoUtils:
    
    def test_generate_salt(self):
        """Teste da geração de salt aleatório."""
        salt1 = CryptoUtils.generate_salt()
        salt2 = CryptoUtils.generate_salt()
        
        assert len(salt1) == CryptoUtils.SALT_SIZE
        assert len(salt2) == CryptoUtils.SALT_SIZE
        assert salt1 != salt2  # Salts devem ser diferentes (probabilisticamente)
    
    def test_generate_iv(self):
        """Teste da geração de IV aleatório."""
        iv1 = CryptoUtils.generate_iv()
        iv2 = CryptoUtils.generate_iv()
        
        assert len(iv1) == CryptoUtils.IV_SIZE
        assert len(iv2) == CryptoUtils.IV_SIZE
        assert iv1 != iv2  # IVs devem ser diferentes (probabilisticamente)
    
    def test_derive_key(self):
        """Teste de derivação de chave."""
        password = "senha_teste"
        salt = b'x' * CryptoUtils.SALT_SIZE
        
        key = CryptoUtils.derive_key(password, salt)
        
        assert len(key) == 32  # 256 bits = 32 bytes
        
        # A mesma senha e salt devem produzir a mesma chave
        key2 = CryptoUtils.derive_key(password, salt)
        assert key == key2
        
        # Senhas diferentes devem produzir chaves diferentes
        key3 = CryptoUtils.derive_key("senha_diferente", salt)
        assert key != key3
    
    def test_encrypt_decrypt_data(self):
        """Teste do ciclo completo de criptografia/descriptografia."""
        test_data = b"Dados de teste para criptografia"
        password = "senha_secreta"
        salt = CryptoUtils.generate_salt()
        iv = CryptoUtils.generate_iv()
        key = CryptoUtils.derive_key(password, salt)
        
        # Criptografia
        encrypted_data = CryptoUtils.encrypt_data(test_data, key, iv)
        assert encrypted_data != test_data  # Dados criptografados devem ser diferentes
        
        # Descriptografia
        decrypted_data = CryptoUtils.decrypt_data(encrypted_data, key, iv)
        assert decrypted_data == test_data  # Dados descriptografados devem igualar os originais
    
    def test_secure_overwrite(self):
        """Teste de limpeza segura de dados sensíveis."""
        sensitive_data = bytearray(b"dados_secretos")
        original_data = sensitive_data.copy()
        
        CryptoUtils.secure_overwrite(sensitive_data)
        
        # Verificar se todos os bytes foram sobrescritos com zeros
        assert all(b == 0 for b in sensitive_data)
        assert sensitive_data != original_data
    
    def test_encrypt_decrypt_empty_data(self):
        """Teste de criptografia/descriptografia de dados vazios."""
        empty_data = b""
        password = "senha_teste"
        salt = CryptoUtils.generate_salt()
        iv = CryptoUtils.generate_iv()
        key = CryptoUtils.derive_key(password, salt)
        
        encrypted_data = CryptoUtils.encrypt_data(empty_data, key, iv)
        decrypted_data = CryptoUtils.decrypt_data(encrypted_data, key, iv)
        
        assert decrypted_data == empty_data
    
    def test_wrong_key_decryption(self):
        """Teste de descriptografia com chave incorreta."""
        test_data = b"Dados de teste"
        correct_key = CryptoUtils.derive_key("senha_correta", CryptoUtils.generate_salt())
        wrong_key = CryptoUtils.derive_key("senha_incorreta", CryptoUtils.generate_salt())
        iv = CryptoUtils.generate_iv()
        
        encrypted_data = CryptoUtils.encrypt_data(test_data, correct_key, iv)
        
        # A descriptografia com chave incorreta deve falhar
        with pytest.raises(Exception):
            CryptoUtils.decrypt_data(encrypted_data, wrong_key, iv)