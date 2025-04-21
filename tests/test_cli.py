import os
import pytest
import tempfile
import shutil
from unittest.mock import patch, MagicMock

from voidbound.cli import CLI


@pytest.fixture
def cli():
    """Fixture para criar uma instância de CLI."""
    return CLI()


@pytest.fixture
def test_dir():
    """Fixture para o diretório de testes."""
    # Usar o diretório de testes existente
    return os.path.join(os.path.dirname(__file__), 'files')


@pytest.fixture
def test_file(test_dir):
    """Fixture para o arquivo de teste."""
    # Usar o arquivo de teste existente
    return os.path.join(test_dir, "test_file.txt")


@pytest.fixture
def temp_dir():
    """Fixture para criar um diretório temporário."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


class TestCLI:
    
    def test_parse_args(self, cli):
        """Teste de análise de argumentos."""
        args = cli.parse_args(['--encrypt', '--input', 'arquivo.txt'])
        assert args['encrypt'] == True
        assert args['decrypt'] == False
        assert args['input'] == 'arquivo.txt'
        assert args['password'] == None
        assert args['output'] == None
        assert args['verbose'] == False
        
        args = cli.parse_args(['-d', '-i', 'arquivo.txt', '-p', 'senha', '-o', 'output_dir', '-v'])
        assert args['encrypt'] == False
        assert args['decrypt'] == True
        assert args['input'] == 'arquivo.txt'
        assert args['password'] == 'senha'
        assert args['output'] == 'output_dir'
        assert args['verbose'] == True
    
    def test_validate_args_success(self, cli, test_file, test_dir):
        """Teste de validação de argumentos válidos."""
        args = {
            'input': test_file,
            'output': test_dir
        }
        # Não deve lançar exceção
        cli.validate_args(args)
    
    def test_validate_args_input_not_exists(self, cli, test_dir):
        """Teste de validação com caminho de entrada inexistente."""
        # Usar um arquivo inexistente dentro do diretório de testes
        args = {
            'input': os.path.join(test_dir, 'arquivo_inexistente.txt'),
            'output': None
        }
        with pytest.raises(ValueError, match="O caminho de entrada não existe"):
            cli.validate_args(args)
    
    def test_validate_args_output_not_directory(self, cli, test_file):
        """Teste de validação com saída não sendo diretório."""
        args = {
            'input': test_file,
            'output': test_file  # Arquivo, não diretório
        }
        with pytest.raises(ValueError, match="O diretório de saída não existe"):
            cli.validate_args(args)
    
    def test_validate_args_with_directory_slash(self, cli, test_dir):
        """Teste de validação com caminho de diretório terminado em /."""
        # Garantir que o caminho termine com /
        dir_with_slash = test_dir + '/'
        args = {
            'input': dir_with_slash,
            'output': None
        }
        cli.validate_args(args)
        # Verificar se o caminho foi normalizado
        assert args['input'] == os.path.normpath(test_dir)
    
    def test_validate_args_with_directory_backslash(self, cli, test_dir):
        """Teste de validação com caminho de diretório terminado em \\."""
        # Garantir que o caminho termine com \ (para Windows)
        dir_with_backslash = test_dir + '\\'
        args = {
            'input': dir_with_backslash,
            'output': None
        }
        cli.validate_args(args)
        # Verificar se o caminho foi normalizado
        assert args['input'] == os.path.normpath(test_dir)
    
    def test_validate_args_slash_not_directory(self, cli, test_file):
        """Teste de validação com caminho terminado em / mas não é diretório."""
        # Criar um caminho de arquivo com / no final
        file_with_slash = test_file + '/'
        args = {
            'input': file_with_slash,
            'output': None
        }
        with pytest.raises(ValueError, match="O caminho especificado deveria ser um diretório"):
            cli.validate_args(args)
    
    @patch('getpass.getpass')
    def test_get_password_provided(self, mock_getpass, cli):
        """Teste de obtenção de senha já fornecida."""
        password = "senha_fornecida"
        result = cli.get_password(password)
        assert result == password
        mock_getpass.assert_not_called()
    
    @patch('getpass.getpass')
    def test_get_password_prompt(self, mock_getpass, cli):
        """Teste de obtenção de senha via prompt."""
        mock_getpass.side_effect = ["senha_digitada", "senha_digitada"]
        
        result = cli.get_password(None)
        
        assert result == "senha_digitada"
        assert mock_getpass.call_count == 2
    
    @patch('getpass.getpass')
    def test_get_password_mismatch(self, mock_getpass, cli):
        """Teste de mismatch de senhas no prompt."""
        mock_getpass.side_effect = ["senha1", "senha2"]
        
        with pytest.raises(ValueError, match="As senhas não correspondem"):
            cli.get_password(None)
    
    @patch('logging.basicConfig')
    def test_setup_logging(self, mock_logging, cli):
        """Teste de configuração de logging."""
        cli.setup_logging(verbose=True)
        mock_logging.assert_called_once()
    
    @patch.object(CLI, 'parse_args')
    @patch.object(CLI, 'validate_args')
    @patch.object(CLI, 'setup_logging')
    @patch.object(CLI, 'get_password')
    @patch('voidbound.file_handler.FileHandler.process_path')
    @patch('logging.info')
    def test_run_success(self, mock_log_info, mock_process_path, mock_get_password, 
                        mock_setup_logging, mock_validate_args, mock_parse_args, cli, test_dir):
        """Teste de execução com sucesso."""
        # Configurar mocks com o caminho de teste correto
        mock_parse_args.return_value = {
            'encrypt': True, 
            'decrypt': False,
            'input': test_dir,
            'output': os.path.join(test_dir, 'output'),
            'password': 'senha',
            'verbose': True
        }
        mock_get_password.return_value = "senha"
        mock_process_path.return_value = ["file1.txt.encrypted", "file2.txt.encrypted"]
        
        # Executar método
        result = cli.run()
        
        # Verificar chamadas e resultado
        mock_parse_args.assert_called_once()
        mock_validate_args.assert_called_once()
        mock_setup_logging.assert_called_once()
        mock_get_password.assert_called_once()
        mock_process_path.assert_called_once_with(
            test_dir, "senha", True, os.path.join(test_dir, 'output'), True
        )
        mock_log_info.assert_called_once()
        assert result == 0
    
    @patch.object(CLI, 'parse_args')
    @patch('logging.error')
    def test_run_error(self, mock_log_error, mock_parse_args, cli):
        """Teste de execução com erro."""
        # Configurar mock para lançar exceção
        mock_parse_args.side_effect = ValueError("Erro de teste")
        
        # Executar método
        result = cli.run()
        
        # Verificar chamadas e resultado
        mock_parse_args.assert_called_once()
        mock_log_error.assert_called_once()
        assert result == 1