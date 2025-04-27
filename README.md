# VoidBound

![VoidBound Logo](assets/icon.png)

## Serviço de Criptografia e Descriptografia de Arquivos

VoidBound é uma ferramenta robusta de criptografia e descriptografia de arquivos desenvolvida em Python. Com suporte a múltiplos algoritmos de criptografia, processamento eficiente de arquivos grandes e recursos avançados de segurança, o VoidBound oferece proteção confiável para seus dados sensíveis.

## ✨ Características Principais

- **Criptografia Forte**: 
  - AES-256 (CBC/GCM)
  - ChaCha20-Poly1305
- **Proteção de Senha**:
  - PBKDF2 com SHA-256 (100.000 iterações)
  - Argon2id (configurável)
- **Versatilidade**:
  - Arquivos individuais ou diretórios completos
  - Arquivamento integrado
  - Processamento de arquivos de até 10GB+
- **Recursos Avançados**:
  - Criptografia híbrida (chave pública/privada)
  - Criptografia de camada dupla
  - Compartimentalização de arquivos grandes
  - Autodestruição programada
  - Backups de emergência com compartilhamento de segredo
  - Assinatura de arquivos
- **Acessibilidade**:
  - Interface de linha de comando (CLI)
  - Interface gráfica (GUI)
  - Multiplataforma (Windows, macOS, Linux)

## 📋 Requisitos

- Python 3.8 ou superior
- Dependências (instaladas automaticamente):
  - cryptography>=36.0.0
  - tqdm>=4.62.0

## 📥 Instalação

### Via pip (recomendado)

```bash
pip install VoidBound
```

### A partir do código fonte

```bash
git clone https://github.com/seu-usuario/voidbound.git
cd voidbound
pip install -r requirements.txt
pip install -e .
```

### Instaladores específicos

- **Windows**: Baixe e execute `VoidBound-Setup.exe` da página de releases

## 🔧 Uso Básico

### Linha de Comando (CLI)

```bash
# Ajuda
voidbound --help

# Criptografar
voidbound --encrypt --input arquivo.txt

# Descriptografar
voidbound --decrypt --input arquivo.txt.encrypted

# Criptografar diretório
voidbound --encrypt --input /caminho/pasta --output /destino

# Criptografar diretório como arquivo único
voidbound --encrypt --archive --input /caminho/pasta --output /destino
```

### Interface Gráfica

```bash
voidbound-gui
```

## 🚀 Recursos Avançados

### Algoritmos de Criptografia Alternativos

```bash
# AES-GCM
voidbound --encrypt --input dados.txt --algorithm aes-gcm

# ChaCha20-Poly1305
voidbound --encrypt --input dados.txt --algorithm chacha20
```

### Funções de Derivação de Chave

```bash
# Argon2id
voidbound --encrypt --input dados.txt --kdf argon2id --memory-cost 131072 --time-cost 4 --parallelism 2
```

### Assinatura Digital

```bash
# Gerar par de chaves
voidbound --generate-keys meu_par_de_chaves

# Criptografar e assinar
voidbound --encrypt --input dados.txt --sign meu_par_de_chaves.private

# Descriptografar e verificar
voidbound --decrypt --input dados.txt.encrypted --verify meu_par_de_chaves.public
```

### Criptografia de Camada Dupla

```bash
# Criptografar com duas senhas
voidbound --encrypt --input arquivo.txt --dual-layer --password "senha1" --password2 "senha2"

# Descriptografar
voidbound --decrypt --input arquivo.txt.dual-encrypted --dual-layer
```

### Compartimentalização

```bash
# Criptografar dividindo em compartimentos
voidbound --encrypt --input video.mp4 --compartmentalize --compartment-size 5242880

# Descriptografar
voidbound --decrypt --input video.mp4.comp-encrypted --compartmentalize
```

### Criptografia Híbrida

```bash
# Gerar pares de chaves
voidbound --generate-keys alice_keys
voidbound --generate-keys bob_keys

# Criptografar para o destinatário
voidbound --encrypt --input secreto.pdf --hybrid --recipient-key bob_keys.public

# Descriptografar
voidbound --decrypt --input secreto.pdf.hybrid-encrypted --hybrid --private-key bob_keys.private
```

### Auto-destruição Programada

```bash
# Expiração em 30 dias
voidbound --encrypt --input documento.pdf --expires +30

# Data específica
voidbound --encrypt --input documento.pdf --expires 2025-12-31

# Verificar expiração
voidbound --check-expiry --input documento.pdf.expires-20251231.encrypted

# Forçar expiração
voidbound --check-expiry --enforce-expiry --input documento.pdf.expires-20251231.encrypted
```

### Backups de Emergência

```bash
# Criptografar com recuperação (5 partes, precisa de 3)
voidbound --encrypt --input dados.txt --with-recovery

# Configurar número de partes
voidbound --encrypt --input dados.txt --with-recovery --recovery-shares 7 --recovery-threshold 4

# Recuperar arquivo com partes
voidbound --decrypt --input dados.txt.recoverable.encrypted --recover-using parte1.key parte2.key parte3.key
```

## 🔐 Detalhes Técnicos

### Estrutura do Arquivo Criptografado

```
[Salt (16 bytes)] + [IV (16 bytes)] + [Dados criptografados]
```

### Considerações de Segurança

- ✅ Senhas nunca são armazenadas, apenas usadas para derivar chaves
- ✅ Dados sensíveis são limpos da memória após o uso
- ⚠️ Não há recuperação sem senha - mantenha backups e senhas seguras
- ✅ Verificação de integridade dos dados criptografados

## ❓ Solução de Problemas

| Problema | Solução |
|----------|---------|
| "Senha incorreta ou arquivo corrompido" | Verifique a senha e a integridade do arquivo |
| "O caminho de entrada não existe" | Confirme que o arquivo ou diretório existe |
| "Erro de permissão" | Execute com privilégios adequados |
| "Memória insuficiente" | Libere memória ou use compartimentalização |

## 🛠️ Desenvolvimento

```bash
# Executar testes
pytest

# Construir executáveis
python builders/build_windows.py  # Windows
python builders/build_macos.py    # macOS
python builders/build_linux.py    # Linux
```

## ⚠️ Aviso de Segurança

**IMPORTANTE**: Arquivos criptografados não podem ser recuperados sem a senha correta. Sempre mantenha backups dos seus dados originais e armazene suas senhas em um gerenciador de senhas seguro.