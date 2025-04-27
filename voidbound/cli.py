import os
import sys
import argparse
import getpass
import logging
import tempfile
from typing import Dict, Any, Optional

from .file_handler import FileHandler


class CLI:
    """Interface de linha de comando para o serviço de criptografia."""
    
    def __init__(self):
        """Inicializa a CLI com parser de argumentos."""
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Cria e configura o parser de argumentos."""
        parser = argparse.ArgumentParser(
            description='Serviço de criptografia/descriptografia de arquivos usando AES-256',
            epilog='IMPORTANTE: Arquivos perdidos não podem ser recuperados sem a senha correta!'
        )
        
        mode_group = parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument('--encrypt', '-e', action='store_true',
                               help='Modo de criptografia')
        mode_group.add_argument('--decrypt', '-d', action='store_true',
                               help='Modo de descriptografia')
        
        parser.add_argument('--input', '-i', required=True,
                           help='Caminho do arquivo ou diretório para processar. Caminhos terminando com / são tratados como diretórios')
        parser.add_argument('--password', '-p',
                           help='Senha para criptografia/descriptografia (omitir para prompt seguro)')
        parser.add_argument('--output', '-o',
                           help='Diretório de saída (opcional; padrão: mesmo diretório da entrada)')
        parser.add_argument('--verbose', '-v', action='store_true',
                           help='Exibir informações detalhadas de processamento')
        parser.add_argument('--archive', '-a', action='store_true',
                           help='Arquivar diretório como um único arquivo antes de criptografar')
        
        # Novos argumentos para algoritmos e KDFs
        crypto_group = parser.add_argument_group('Opções de criptografia')
        crypto_group.add_argument('--algorithm', choices=['aes-cbc', 'aes-gcm', 'chacha20'], 
                                default='aes-cbc', help='Algoritmo de criptografia')
        crypto_group.add_argument('--kdf', choices=['pbkdf2', 'argon2id', 'scrypt'], 
                                default='pbkdf2', help='Função de derivação de chave')
        
        # Parâmetros de KDF
        kdf_group = parser.add_argument_group('Parâmetros de KDF')
        kdf_group.add_argument('--iterations', type=int, help='Número de iterações para PBKDF2')
        kdf_group.add_argument('--memory-cost', type=int, help='Custo de memória para Argon2id (KB)')
        kdf_group.add_argument('--time-cost', type=int, help='Custo de tempo para Argon2id')
        kdf_group.add_argument('--parallelism', type=int, help='Paralelismo para Argon2id')
        
        # Opções de assinatura digital
        sign_group = parser.add_argument_group('Assinatura Digital')
        sign_group.add_argument('--sign', help='Arquivo com chave privada para assinar')
        sign_group.add_argument('--verify', help='Arquivo com chave pública para verificar')
        sign_group.add_argument('--generate-keys', help='Gerar par de chaves e salvar com prefixo')
 
        return parser
    
    def parse_args(self, args=None) -> Dict[str, Any]:
        """
        Analisa os argumentos da linha de comando.
        
        Args:
            args: Lista de argumentos (opcional, usa sys.argv se None).
            
        Returns:
            Dicionário com os argumentos analisados.
        """
        parsed_args = self.parser.parse_args(args)
        result = vars(parsed_args)
        
        # Configurar os parâmetros do KDF
        result['kdf_params'] = {}
        if parsed_args.iterations:
            result['kdf_params']['iterations'] = parsed_args.iterations
        if parsed_args.memory_cost:
            result['kdf_params']['memory_cost'] = parsed_args.memory_cost
        if parsed_args.time_cost:
            result['kdf_params']['time_cost'] = parsed_args.time_cost
        if parsed_args.parallelism:
            result['kdf_params']['parallelism'] = parsed_args.parallelism
        
        # Se não especificado, o modo padrão é criptografia
        if not result['encrypt'] and not result['decrypt']:
            result['encrypt'] = True
        
        return result
    
    def validate_args(self, args: Dict[str, Any]) -> None:
        """
        Valida os argumentos fornecidos.
        
        Args:
            args: Dicionário com os argumentos analisados.
            
        Raises:
            ValueError: Se os argumentos forem inválidos.
        """
        input_path = args['input']
        
        # Normalizar o caminho e verificar se termina com / ou \
        input_path = os.path.normpath(input_path)
        
        # Se o caminho original terminava com / ou \, garantir que seja tratado como diretório
        if args['input'].endswith('/') or args['input'].endswith('\\'):
            if not os.path.isdir(input_path):
                raise ValueError(f"O caminho especificado deveria ser um diretório: {args['input']}")
            args['input'] = input_path
        
        # Verificar se o caminho de entrada existe
        if not os.path.exists(args['input']):
            raise ValueError(f"O caminho de entrada não existe: {args['input']}")
        
        # Verificar se o diretório de saída existe (se fornecido)
        if args['output'] and not os.path.isdir(args['output']):
            raise ValueError(f"O diretório de saída não existe: {args['output']}")
    
    def get_password(self, provided_password: Optional[str] = None) -> str:
        """
        Obtém a senha do usuário.
        
        Args:
            provided_password: Senha fornecida como argumento (opcional).
            
        Returns:
            Senha fornecida ou solicitada.
        """
        if provided_password:
            return provided_password
        
        # Solicitar senha de forma segura (não exibe na tela)
        password = getpass.getpass("Digite a senha: ")
        if not password:
            raise ValueError("A senha não pode estar vazia")
        
        # Solicitar confirmação para criptografia
        confirm = getpass.getpass("Confirme a senha: ")
        if password != confirm:
            raise ValueError("As senhas não correspondem")
        
        return password
    
    def setup_logging(self, verbose: bool) -> None:
        """
        Configura o logging com base no nível de verbosidade.
        
        Args:
            verbose: Se True, define o nível de log como DEBUG.
        """
        level = logging.DEBUG if verbose else logging.INFO
        format_str = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=level, format=format_str)
    
    def run(self, args=None) -> int:
        """
        Executa o processo de criptografia/descriptografia com base nos argumentos.
        
        Args:
            args: Lista de argumentos (opcional).
            
        Returns:
            Código de saída (0 para sucesso, 1 para erro).
        """
        parsed_args = None  # Inicialização antes do bloco try
        temp_file = None
        
        try:
            # Analisar e validar argumentos
            parsed_args = self.parse_args(args)
            self.validate_args(parsed_args)
            
            # Configurar logging
            self.setup_logging(parsed_args['verbose'])
            
            # Obter senha
            password = self.get_password(parsed_args['password'])
            
            # Determinar modo
            encrypt = parsed_args['encrypt']
            
            # Processar arquivos
            if encrypt and parsed_args.get('archive') and os.path.isdir(parsed_args['input']):
                # Modo de arquivamento + criptografia
                if parsed_args['verbose']:
                    logging.info(f"Empacotando diretório {parsed_args['input']}...")
                
                # Criar nome para o arquivo de saída
                input_basename = os.path.basename(parsed_args['input'].rstrip('\\/'))
                output_dir = parsed_args['output'] if parsed_args['output'] else os.path.dirname(parsed_args['input'])
                
                # Arquivar diretório
                temp_file = FileHandler.archive_directory(parsed_args['input'], None)
                
                if parsed_args['verbose']:
                    logging.info(f"Diretório empacotado temporariamente como {temp_file}")
                    logging.info("Criptografando arquivo...")
                
                # Criar caminho de saída final
                final_output = os.path.join(output_dir, f"{input_basename}.encrypted")
                
                # Criptografar o arquivo temporário
                FileHandler.encrypt_file(temp_file, password, final_output, parsed_args['verbose'])
                
                # Limpar arquivo temporário
                os.unlink(temp_file)
                
                logging.info(f"Diretório {parsed_args['input']} arquivado e criptografado como {final_output}")
            elif not encrypt and FileHandler.is_encrypted_file(parsed_args['input']) and parsed_args.get('archive'):
                # Modo de descriptografia + descompactação
                if parsed_args['verbose']:
                    logging.info(f"Descriptografando arquivo {parsed_args['input']}...")
                
                # Criar diretório de saída
                output_dir = parsed_args['output'] if parsed_args['output'] else os.path.dirname(parsed_args['input'])
                
                # Descriptografar para arquivo temporário
                temp_file = tempfile.NamedTemporaryFile(delete=False).name
                FileHandler.decrypt_file(parsed_args['input'], password, temp_file, parsed_args['verbose'])
                
                if parsed_args['verbose']:
                    logging.info(f"Arquivo descriptografado temporariamente como {temp_file}")
                    logging.info("Extraindo arquivo...")
                
                # Extrair arquivo
                FileHandler.extract_archive(temp_file, output_dir)
                
                # Limpar arquivo temporário
                os.unlink(temp_file)
                
                logging.info(f"Arquivo {parsed_args['input']} descriptografado e extraído em {output_dir}")
            else:
                # Modo padrão: processar arquivo ou diretório
                processed_files = FileHandler.process_path(
                    parsed_args['input'],
                    password,
                    encrypt,
                    parsed_args['output'],
                    parsed_args['verbose']
                )
                
                # Exibir resumo
                operation = "criptografados" if encrypt else "descriptografados"
                logging.info(f"{len(processed_files)} arquivos {operation} com sucesso.")
            
            return 0
        
        except Exception as e:
            logging.error(f"Erro: {str(e)}")
            if parsed_args and parsed_args.get('verbose'):
                logging.exception("Detalhes do erro:")
            
            # Limpar arquivo temporário em caso de erro
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)
                
            return 1