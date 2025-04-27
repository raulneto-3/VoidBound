import os
import sys
import argparse
import getpass
import logging
import tempfile
from typing import Dict, Any, Optional
from .crypto_utils import CryptoUtils  # Import CryptoUtils from the appropriate module
import datetime
from typing import List, Tuple

from .file_handler import FileHandler


class CLI:
    """Interface de linha de comando para o serviço de criptografia."""
    
    def __init__(self):
        """Inicializa a CLI com parser de argumentos."""
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Cria e configura o parser de argumentos."""
        parser = argparse.ArgumentParser(
            description='VoidBound - Serviço de Criptografia/Descriptografia de Arquivos'
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
        
        # Novo grupo para recursos avançados
        advanced_group = parser.add_argument_group('Recursos Avançados')
        
        # Opções para criptografia de camada dupla
        dual_group = advanced_group.add_argument_group('Criptografia de Camada Dupla')
        dual_group.add_argument('--dual-layer', action='store_true', 
                              help='Ativar criptografia com proteção de camada dupla')
        dual_group.add_argument('--password2', help='Segunda senha para camada dupla')
        dual_group.add_argument('--layer1-algo', choices=['aes-cbc', 'aes-gcm', 'chacha20'],
                              default='aes-gcm', help='Algoritmo para primeira camada')
        dual_group.add_argument('--layer2-algo', choices=['aes-cbc', 'aes-gcm', 'chacha20'],
                              default='chacha20', help='Algoritmo para segunda camada')
        
        # Opções para criptografia híbrida
        hybrid_group = advanced_group.add_argument_group('Criptografia Híbrida')
        hybrid_group.add_argument('--hybrid', action='store_true',
                                help='Ativar criptografia híbrida (assimétrica+simétrica)')
        hybrid_group.add_argument('--recipient-key', 
                                help='Caminho para a chave pública do destinatário')
        hybrid_group.add_argument('--private-key',
                                help='Caminho para a chave privada (descriptografia)')
        
        # Opções para compartimentalização
        comp_group = advanced_group.add_argument_group('Compartimentalização')
        comp_group.add_argument('--compartmentalize', action='store_true',
                              help='Ativar compartimentalização de arquivo')
        comp_group.add_argument('--compartment-size', type=int, default=10*1024*1024,
                              help='Tamanho de cada compartimento em bytes (padrão: 10MB)')
        
        # Grupo para auto-destruição programada
        expiry_group = parser.add_argument_group('Auto-destruição Programada')
        expiry_group.add_argument('--expires', help='Data de expiração no formato YYYY-MM-DD ou +dias')
        expiry_group.add_argument('--check-expiry', action='store_true', 
                                help='Apenas verificar se um arquivo expirou')
        expiry_group.add_argument('--enforce-expiry', action='store_true', 
                                help='Excluir automaticamente arquivos expirados')
        expiry_group.add_argument('--allow-expired', action='store_true', 
                                help='Permitir descriptografia de arquivos expirados')
        
        # Grupo para recuperação de emergência
        recovery_group = parser.add_argument_group('Backup de Emergência')
        recovery_group.add_argument('--with-recovery', action='store_true', 
                                  help='Habilitar recuperação de emergência')
        recovery_group.add_argument('--recovery-shares', type=int, default=5, 
                                  help='Número total de partes da chave de recuperação')
        recovery_group.add_argument('--recovery-threshold', type=int, default=3, 
                                  help='Número mínimo de partes para recuperação')
        recovery_group.add_argument('--recovery-dir', 
                                  help='Diretório para salvar as partes da chave de recuperação')
        recovery_group.add_argument('--recover-using', nargs='+', 
                                  help='Caminhos para as partes da chave de recuperação')
 
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
        if not result['encrypt'] and not result['decrypt'] and not result['check_expiry']:
            result['encrypt'] = True
        
        # Processar a opção de expiração
        if result['expires']:
            try:
                if result['expires'].startswith('+'):
                    # Formato +dias
                    days = int(result['expires'][1:])
                    result['expiration_date'] = datetime.datetime.now() + datetime.timedelta(days=days)
                else:
                    # Formato YYYY-MM-DD
                    result['expiration_date'] = datetime.datetime.strptime(result['expires'], "%Y-%m-%d")
            except ValueError:
                parser.error("Formato de data de expiração inválido. Use YYYY-MM-DD ou +dias.")
        
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
            
            # === ADIÇÃO DE CÓDIGO PARA RECURSOS AVANÇADOS ===
            
            # Verificar se está usando recursos avançados
            if parsed_args.get('dual_layer'):
                if parsed_args.get('encrypt'):
                    # Verificar se a segunda senha foi fornecida
                    if not parsed_args.get('password2'):
                        if parsed_args.get('password'):
                            # Pedir a segunda senha interativamente
                            parsed_args['password2'] = self.get_password(
                                "Digite a segunda senha (camada 2): ", confirm=True
                            )
                        else:
                            # Pedir ambas as senhas interativamente
                            parsed_args['password'] = self.get_password(
                                "Digite a primeira senha (camada 1): ", confirm=True
                            )
                            parsed_args['password2'] = self.get_password(
                                "Digite a segunda senha (camada 2): ", confirm=True
                            )
                    
                    # Executar criptografia de camada dupla
                    output_path = FileHandler.dual_layer_encrypt_file(
                        parsed_args['input'],
                        parsed_args['password'],
                        parsed_args['password2'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False),
                        parsed_args.get('layer1_algo', CryptoUtils.ALG_AES_GCM),
                        parsed_args.get('layer2_algo', CryptoUtils.ALG_CHACHA20)
                    )
                    
                    if parsed_args.get('verbose'):
                        print(f"Arquivo criptografado com camada dupla: {output_path}")
                    
                    return 0
                    
                elif parsed_args.get('decrypt'):
                    # Verificar se as senhas foram fornecidas
                    if not parsed_args.get('password'):
                        parsed_args['password'] = self.get_password("Digite a primeira senha (camada 1): ")
                    if not parsed_args.get('password2'):
                        parsed_args['password2'] = self.get_password("Digite a segunda senha (camada 2): ")
                    
                    # Executar descriptografia de camada dupla
                    output_path = FileHandler.dual_layer_decrypt_file(
                        parsed_args['input'],
                        parsed_args['password'],
                        parsed_args['password2'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False)
                    )
                    
                    if parsed_args.get('verbose'):
                        print(f"Arquivo descriptografado com sucesso: {output_path}")
                    
                    return 0
            
            # Verificar se está usando criptografia híbrida
            elif parsed_args.get('hybrid'):
                if parsed_args.get('encrypt'):
                    # Verificar se a chave pública do destinatário foi fornecida
                    if not parsed_args.get('recipient_key'):
                        raise ValueError("É necessário fornecer a chave pública do destinatário (--recipient-key)")
                    
                    # Executar criptografia híbrida
                    output_path = FileHandler.hybrid_encrypt_file(
                        parsed_args['input'],
                        parsed_args['recipient_key'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False),
                        parsed_args.get('algorithm', CryptoUtils.ALG_AES_GCM)
                    )
                    
                    if parsed_args.get('verbose'):
                        print(f"Arquivo criptografado com criptografia híbrida: {output_path}")
                    
                    return 0
                    
                elif parsed_args.get('decrypt'):
                    # Verificar se a chave privada foi fornecida
                    if not parsed_args.get('private_key'):
                        raise ValueError("É necessário fornecer sua chave privada (--private-key)")
                    
                    # Executar descriptografia híbrida
                    output_path = FileHandler.hybrid_decrypt_file(
                        parsed_args['input'],
                        parsed_args['private_key'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False)
                    )
                    
                    if parsed_args.get('verbose'):
                        print(f"Arquivo descriptografado com sucesso: {output_path}")
                    
                    return 0
            
            # Verificar se está usando compartimentalização
            elif parsed_args.get('compartmentalize'):
                if parsed_args.get('encrypt'):
                    # Verificar se a senha foi fornecida
                    if not parsed_args.get('password'):
                        parsed_args['password'] = self.get_password("Digite a senha: ", confirm=True)
                    
                    # Executar criptografia com compartimentalização
                    output_path = FileHandler.compartmentalized_encrypt_file(
                        parsed_args['input'],
                        parsed_args['password'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False),
                        parsed_args.get('algorithm', CryptoUtils.ALG_AES_GCM),
                        parsed_args.get('kdf', CryptoUtils.KDF_PBKDF2),
                        parsed_args.get('compartment_size', CryptoUtils.COMPARTMENT_SIZE)
                    )
                    
                    if parsed_args.get('verbose'):
                        print(f"Arquivo criptografado com compartimentalização: {output_path}")
                    
                    return 0
                    
                elif parsed_args.get('decrypt'):
                    # Verificar se a senha foi fornecida
                    if not parsed_args.get('password'):
                        parsed_args['password'] = self.get_password("Digite a senha: ")
                    
                    # Executar descriptografia com compartimentalização
                    output_path = FileHandler.compartmentalized_decrypt_file(
                        parsed_args['input'],
                        parsed_args['password'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False)
                    )
                    
                    if parsed_args.get('verbose'):
                        print(f"Arquivo descriptografado com sucesso: {output_path}")
                    
                    return 0
            
            # Se não estiver usando recursos avançados, continuar com o processamento normal
            
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
            
            # AUTO-DESTRUIÇÃO PROGRAMADA
            if parsed_args.get('check_expiry'):
                if not os.path.exists(parsed_args['input']):
                    print(f"Erro: O arquivo {parsed_args['input']} não existe.")
                    return 1
                    
                expired, message = FileHandler.check_file_expiration(
                    parsed_args['input'], 
                    parsed_args.get('verbose', False),
                    parsed_args.get('enforce_expiry', False)
                )
                
                if expired:
                    print(f"AVISO: {message}")
                    return 1  # Retornar código de erro se o arquivo expirou
                else:
                    print(f"Informação: {message}")
                    return 0
            
            # RECUPERAÇÃO DE EMERGÊNCIA
            if parsed_args.get('recover_using'):
                if not parsed_args.get('decrypt'):
                    print("A opção --recover-using deve ser usada com --decrypt")
                    return 1
                    
                try:
                    # Verificar se todos os arquivos de recuperação existem
                    for share_file in parsed_args['recover_using']:
                        if not os.path.exists(share_file):
                            print(f"Erro: Arquivo de recuperação não encontrado: {share_file}")
                            return 1
                    
                    output_path = FileHandler.decrypt_with_recovery_keys(
                        parsed_args['input'],
                        parsed_args['recover_using'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False)
                    )
                    
                    print(f"Arquivo recuperado com sucesso: {output_path}")
                    return 0
                    
                except Exception as e:
                    print(f"Erro na recuperação de emergência: {str(e)}")
                    return 1
            
            # Obter senha para operações normais
            if not parsed_args.get('recover_using'):
                password = self.get_password(parsed_args['password'])
            
            # CRIPTOGRAFIA COM EXPIRAÇÃO
            if parsed_args.get('encrypt') and parsed_args.get('expiration_date'):
                try:
                    output_path = FileHandler.encrypt_file_with_expiration(
                        parsed_args['input'],
                        password,
                        parsed_args['expiration_date'],
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False),
                        parsed_args.get('algorithm', CryptoUtils.DEFAULT_ALGORITHM),
                        parsed_args.get('kdf', CryptoUtils.DEFAULT_KDF)
                    )
                    
                    print(f"Arquivo criptografado com expiração: {output_path}")
                    print(f"Data de expiração: {parsed_args['expiration_date'].strftime('%Y-%m-%d %H:%M:%S')}")
                    return 0
                    
                except Exception as e:
                    print(f"Erro ao criptografar com expiração: {str(e)}")
                    return 1
            
            # CRIPTOGRAFIA COM RECUPERAÇÃO
            elif parsed_args.get('encrypt') and parsed_args.get('with_recovery'):
                try:
                    output_path, share_paths = FileHandler.encrypt_file_with_recovery(
                        parsed_args['input'],
                        password,
                        parsed_args.get('output'),
                        parsed_args.get('verbose', False),
                        parsed_args.get('algorithm', CryptoUtils.DEFAULT_ALGORITHM),
                        parsed_args.get('recovery_shares', CryptoUtils.RECOVERY_SHARES),
                        parsed_args.get('recovery_threshold', CryptoUtils.RECOVERY_THRESHOLD),
                        True,  # Sempre salvar as partes
                        parsed_args.get('recovery_dir')
                    )
                    
                    print(f"Arquivo criptografado com recuperação de emergência: {output_path}")
                    print(f"Partes da chave de recuperação (guarde-as em locais separados):")
                    for i, path in enumerate(share_paths):
                        print(f"  {i+1}. {path}")
                    print(f"\nIMPORTANTE: São necessárias pelo menos {parsed_args.get('recovery_threshold')} " +
                          f"partes para recuperar o arquivo em caso de perda de senha.")
                    return 0
                    
                except Exception as e:
                    print(f"Erro ao criptografar com recuperação: {str(e)}")
                    return 1
            
            # DESCRIPTOGRAFIA COM VERIFICAÇÃO DE EXPIRAÇÃO
            elif parsed_args.get('decrypt'):
                try:
                    # Verificar se o arquivo existe
                    if not os.path.exists(parsed_args['input']):
                        print(f"Erro: O arquivo {parsed_args['input']} não existe.")
                        return 1
                    
                    # Verificar se o arquivo tem metadados de expiração
                    with open(parsed_args['input'], 'rb') as f:
                        header_data = f.read(8192)
                    metadata, _ = FileFormat.unpack_header(header_data)
                    
                    if metadata.get("expiration", {}).get("enabled", False):
                        # Descriptografar com verificação de expiração
                        output_path = FileHandler.decrypt_with_expiration_check(
                            parsed_args['input'],
                            password,
                            parsed_args.get('output'),
                            parsed_args.get('verbose', False),
                            parsed_args.get('allow_expired', False)
                        )
                    else:
                        # Descriptografia normal
                        output_path = FileHandler.decrypt_file(
                            parsed_args['input'],
                            password,
                            parsed_args.get('output'),
                            parsed_args.get('verbose', False)
                        )
                    
                    print(f"Arquivo descriptografado: {output_path}")
                    return 0
                    
                except ValueError as e:
                    print(f"Erro: {str(e)}")
                    return 1
            
            # Processamento existente para outros casos...
            
        except Exception as e:
            logging.error(f"Erro: {str(e)}")
            if parsed_args and parsed_args.get('verbose'):
                logging.exception("Detalhes do erro:")
            
            # Limpar arquivo temporário em caso de erro
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)
                
            return 1