# VoidBound

## Serviço de Criptografia/Descriptografia de Arquivos

VoidBound é uma ferramenta robusta de criptografia e descriptografia de arquivos desenvolvida em Python. Utilizando o algoritmo AES-256 em modo CBC com preenchimento PKCS7, o VoidBound oferece uma solução segura para proteção de dados sensíveis, seja através de interface de linha de comando ou interface gráfica.

![VoidBound Logo](assets/icon.png)

## Características Principais

- **Criptografia Forte**: AES-256 em modo CBC com preenchimento PKCS7
- **Derivação Segura de Chave**: PBKDF2HMAC com SHA-256, salt aleatório e 100.000 iterações
- **Processamento Eficiente**: Manipulação de arquivos em blocos para suportar arquivos grandes (até 10GB+)
- **Modos de Operação**: Criptografar/descriptografar arquivos individuais ou diretórios completos (recursivamente)
- **Arquivamento Integrado**: Empacote diretórios inteiros em um único arquivo criptografado
- **Interface Dupla**: CLI para automação e GUI para uso simplificado
- **Multiplataforma**: Suporte para Windows, macOS e Linux
- **Preservação de Metadados**: Mantém permissões e datas de modificação dos arquivos originais

## Requisitos

- Python 3.8 ou superior
- Dependências (instaladas automaticamente):
  - cryptography>=36.0.0
  - tqdm>=4.62.0

## Instalação

### Método 1: Via pip (recomendado)

```bash
pip install VoidBound
```

### Método 2: A partir do código fonte

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/voidbound.git
cd voidbound

# Instalar dependências
pip install -r requirements.txt

# Instalar o pacote
pip install -e .
```

### Método 3: Instaladores específicos para cada plataforma

#### Windows
- Baixe o instalador `VoidBound-Setup.exe` da página de releases
- Execute o instalador e siga as instruções na tela
<!-- 
#### macOS
- Baixe `VoidBound-macOS.tar.gz` da página de releases
- Extraia o arquivo e execute `sudo ./install.sh`

#### Linux (Debian/Ubuntu)
- Baixe `voidbound_1.0.0_amd64.deb` da página de releases
- Execute `sudo dpkg -i voidbound_1.0.0_amd64.deb`

#### Outras distribuições Linux
- Baixe `VoidBound-Linux.tar.gz` da página de releases
- Extraia o arquivo e execute `sudo ./install.sh` -->

## Uso

### Interface de Linha de Comando (CLI)

```bash
# Visualizar ajuda
voidbound --help

# Criptografar um arquivo
voidbound --encrypt --input arquivo.txt

# Descriptografar um arquivo
voidbound --decrypt --input arquivo.txt.encrypted

# Criptografar um diretório inteiro
voidbound --encrypt --input /caminho/pasta --output /destino

# Criptografar um diretório como um único arquivo
voidbound --encrypt --archive --input /caminho/pasta --output /destino

# Criptografar com senha específica (não recomendado em produção)
voidbound --encrypt --input arquivo.txt --password minhasenha

# Modo detalhado (verbose)
voidbound --encrypt --input arquivo.txt --verbose
```

## Exemplos

### Exemplo 1: Criptografar arquivos confidenciais

```bash
voidbound --encrypt --input documentos_confidenciais/ --output documentos_seguros/
```

### Exemplo 2: Descriptografar arquivos previamente criptografados

```bash
voidbound --decrypt --input backup.zip.encrypted
```

### Exemplo 3: Arquivar e criptografar uma estrutura de diretórios como um único arquivo

```bash
voidbound --encrypt --archive --input /dados/confidenciais --output /destino/seguro/
```

Isso criará um único arquivo `/destino/seguro/confidenciais.encrypted` contendo toda a estrutura de diretórios criptografada.


### Interface Gráfica (GUI)

Para iniciar a interface gráfica:

```bash
voidbound-gui
```

Ou no Windows, use o atalho criado no Menu Iniciar ou na Área de Trabalho.

## Exemplos

### Exemplo 1: Criptografar arquivos confidenciais

```bash
voidbound --encrypt --input documentos_confidenciais/ --output documentos_seguros/
```

### Exemplo 2: Descriptografar arquivos previamente criptografados

```bash
voidbound --decrypt --input backup.zip.encrypted
```

## Estrutura do Arquivo Criptografado

Os arquivos criptografados seguem a estrutura:
```
[Salt (16 bytes)] + [IV (16 bytes)] + [Dados criptografados]
```

Essa estrutura garante que cada arquivo tenha seu próprio salt e IV, aumentando significativamente a segurança.

## Considerações de Segurança

- **Proteção de Senha**: Nunca armazenamos sua senha. Ela é usada apenas para derivar a chave de criptografia.
- **Limpeza de Memória**: Dados sensíveis (senhas, chaves) são sobrescritos na memória após o uso.
- **Sem Recuperação**: Não há como recuperar arquivos se a senha for perdida. Guarde suas senhas com segurança.
- **Criptografia Verificável**: A implementação permite verificar se a senha está correta antes de completar a descriptografia.

## Solução de Problemas

| Problema | Possível Solução |
|----------|------------------|
| "Senha incorreta ou arquivo corrompido" | Verifique se a senha está correta e se o arquivo não foi modificado |
| "O caminho de entrada não existe" | Verifique se o arquivo ou diretório especificado existe |
| "Erro de permissão" | Execute o programa com privilégios adequados para acessar os arquivos |
| "Memória insuficiente" | Para arquivos muito grandes, libere memória ou use um computador com mais recursos |

## Desenvolvimento

### Executar os testes

```bash
pytest
```

### Construir executáveis

```bash
# Windows
python builders/build_windows.py

# macOS
python builders/build_macos.py

# Linux
python builders/build_linux.py
```

## Aviso de Segurança

**IMPORTANTE**: Arquivos criptografados não podem ser recuperados sem a senha correta. Sempre mantenha backups dos seus dados originais e guarde suas senhas em um local seguro.