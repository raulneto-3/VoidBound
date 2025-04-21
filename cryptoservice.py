#!/usr/bin/env python3
"""
VoidBound - Serviço de Criptografia/Descriptografia de Arquivos

Este script fornece uma interface de linha de comando para criptografar e
descriptografar arquivos usando AES-256 em modo CBC com derivação de chave PBKDF2.
"""

import sys
from voidbound.cli import CLI


def main():
    """
    Função principal que executa o serviço de criptografia.
    
    Returns:
        Código de saída (0 para sucesso, 1 para erro).
    """
    cli = CLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())