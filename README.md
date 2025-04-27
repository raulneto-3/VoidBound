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



### Criptografia com AES-GCM:
```bash
voidbound --encrypt --input dados.txt --algorithm aes-gcm
```

### Criptografia com ChaCha20-Poly1305:
```bash
voidbound --encrypt --input dados.txt --algorithm chacha20
```

### Usando Argon2id com parâmetros personalizados:
```bash
voidbound --encrypt --input dados.txt --kdf argon2id --memory-cost 131072 --time-cost 4 --parallelism 2
```

### Gerando um par de chaves para assinaturas:
```bash
voidbound --generate-keys meu_par_de_chaves
```

### Criptografando e assinando um arquivo:
```bash
voidbound --encrypt --input dados.txt --sign meu_par_de_chaves.private
```

### Descriptografando e verificando um arquivo assinado:
```bash
voidbound --decrypt --input dados.txt.encrypted --verify meu_par_de_chaves.public
```


### 1. Criptografia de Camada Dupla

```bash
# Criptografar usando duas senhas diferentes
voidbound --encrypt --input arquivo.txt --dual-layer --password "senha1" --password2 "senha2"

# Descriptografar arquivo de camada dupla
voidbound --decrypt --input arquivo.txt.dual-encrypted --dual-layer
```

### 2. Compartimentalização (para arquivos grandes)

```bash
# Criptografar dividindo em compartimentos de 5MB
voidbound --encrypt --input video.mp4 --compartmentalize --compartment-size 5242880

# Descriptografar arquivo compartimentado
voidbound --decrypt --input video.mp4.comp-encrypted --compartmentalize
```

### 3. Criptografia Híbrida (para compartilhamento seguro)

```bash
# Gerar par de chaves para Alice
voidbound --generate-keys alice_keys

# Gerar par de chaves para Bob
voidbound --generate-keys bob_keys

# Alice criptografa um arquivo para Bob
voidbound --encrypt --input secreto.pdf --hybrid --recipient-key bob_keys.public

# Bob descriptografa o arquivo usando sua chave privada
voidbound --decrypt --input secreto.pdf.hybrid-encrypted --hybrid --private-key bob_keys.private
```


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



### Auto-destruição Programada

```bash
# Criptografar um arquivo que expira em 30 dias
voidbound --encrypt --input documento.pdf --expires +30

# Criptografar um arquivo com data específica de expiração
voidbound --encrypt --input documento.pdf --expires 2025-12-31

# Verificar se um arquivo expirou
voidbound --check-expiry --input documento.pdf.expires-20251231.encrypted

# Verificar e excluir arquivos expirados
voidbound --check-expiry --enforce-expiry --input documento.pdf.expires-20251231.encrypted

# Descriptografar, permitindo acesso mesmo se expirado
voidbound --decrypt --input documento.pdf.expires-20251231.encrypted --allow-expired
```

### Backups de Emergência

```bash
# Criptografar com recuperação de emergência (5 partes, precisa de 3)
voidbound --encrypt --input dados_importantes.zip --with-recovery

# Especificar número de partes e limiar
voidbound --encrypt --input dados_importantes.zip --with-recovery --recovery-shares 7 --recovery-threshold 4

# Armazenar partes em diretório específico
voidbound --encrypt --input dados_importantes.zip --with-recovery --recovery-dir /backup/keys

# Recuperar arquivo usando partes de recuperação (sem senha)
voidbound --decrypt --input dados_importantes.zip.recoverable.encrypted \
  --recover-using \
  backup1.key backup2.key backup3.key
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
