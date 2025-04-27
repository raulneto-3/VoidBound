import struct
import json
import base64
from typing import Dict, Any, Tuple, Optional, Union


class FileFormat:
    """
    Classe para manipular o formato de arquivo criptografado do VoidBound.
    
    Novo formato:
    [Magic Bytes (8)] + [Versão (2)] + [Tamanho dos Metadados (4)] + 
    [Metadados JSON] + [Dados Criptografados]
    
    Os metadados JSON contêm informações como o algoritmo, modo, KDF,
    salt, iv/nonce, e opcionalmente assinatura e outros parâmetros.
    """
    
    # Magic bytes para identificação do formato VoidBound
    MAGIC = b'VOIDBND1'
    
    # Versão atual do formato
    VERSION = 2  # Versão 1 era o formato antigo sem metadados
    
    @staticmethod
    def pack_header(metadata: Dict[str, Any]) -> bytes:
        """
        Cria o cabeçalho do arquivo com os metadados.
        
        Args:
            metadata: Dicionário com os metadados
            
        Returns:
            Cabeçalho como bytes
        """
        # Converter metadados para JSON e depois bytes
        metadata_json = json.dumps(metadata)
        metadata_bytes = metadata_json.encode('utf-8')
        
        # Montar cabeçalho: magic + versão + tamanho + metadados
        header = (
            FileFormat.MAGIC +
            struct.pack('<H', FileFormat.VERSION) +
            struct.pack('<I', len(metadata_bytes)) +
            metadata_bytes
        )
        
        return header
    
    @staticmethod
    def unpack_header(data: bytes) -> Tuple[Dict[str, Any], int]:
        """
        Extrai os metadados do cabeçalho do arquivo.
        
        Args:
            data: Os primeiros bytes do arquivo
            
        Returns:
            Tupla (metadados, posição onde os dados criptografados começam)
        """
        # Verificar magic bytes
        if data[:len(FileFormat.MAGIC)] != FileFormat.MAGIC:
            # Tentar formato antigo (sem metadados)
            return FileFormat._handle_legacy_format(data)
        
        # Ler versão
        version = struct.unpack('<H', data[len(FileFormat.MAGIC):len(FileFormat.MAGIC)+2])[0]
        
        # Verificar versão
        if version != FileFormat.VERSION:
            raise ValueError(f"Versão de arquivo não suportada: {version}")
        
        # Ler tamanho dos metadados
        metadata_size = struct.unpack('<I', data[len(FileFormat.MAGIC)+2:len(FileFormat.MAGIC)+6])[0]
        
        # Ler metadados
        metadata_start = len(FileFormat.MAGIC) + 6
        metadata_end = metadata_start + metadata_size
        metadata_json = data[metadata_start:metadata_end].decode('utf-8')
        metadata = json.loads(metadata_json)
        
        # Retornar metadados e posição onde começam os dados criptografados
        return metadata, metadata_end
    
    @staticmethod
    def _handle_legacy_format(data: bytes) -> Tuple[Dict[str, Any], int]:
        """
        Trata o formato antigo do VoidBound (sem metadados).
        
        No formato antigo, os primeiros 16 bytes eram o salt,
        seguidos por 16 bytes de IV e depois os dados criptografados.
        
        Args:
            data: Os primeiros bytes do arquivo
            
        Returns:
            Tupla (metadados no novo formato, posição onde os dados criptografados começam)
        """
        # Extrair salt e IV do formato antigo
        salt = data[:16]
        iv = data[16:32]
        
        # Criar metadados compatíveis com o novo formato
        metadata = {
            "algorithm": "aes-cbc",  # Algoritmo usado no formato antigo
            "kdf": "pbkdf2",         # KDF usado no formato antigo
            "salt": base64.b64encode(salt).decode('ascii'),
            "iv": base64.b64encode(iv).decode('ascii'),
            "iterations": 100000,    # Valor padrão do formato antigo
            "legacy_format": True    # Marcar como formato legado
        }
        
        # No formato antigo, os dados criptografados começam após salt+iv (32 bytes)
        return metadata, 32