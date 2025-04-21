import os
import sys
import subprocess
import shutil
import platform

# Verifica se estamos no Linux
if platform.system() != "Linux":
    print("Este script deve ser executado no Linux.")
    sys.exit(1)

# Verifica se PyInstaller está instalado
try:
    import PyInstaller
except ImportError:
    print("Instalando PyInstaller...")
    subprocess.call([sys.executable, "-m", "pip", "install", "pyinstaller"])

# Cria pasta de build se não existir
if not os.path.exists("build"):
    os.mkdir("build")
if not os.path.exists("build/linux"):
    os.mkdir("build/linux")
if not os.path.exists("build/linux/DEBIAN"):
    os.mkdir("build/linux/DEBIAN")
if not os.path.exists("build/linux/usr"):
    os.mkdir("build/linux/usr")
if not os.path.exists("build/linux/usr/bin"):
    os.mkdir("build/linux/usr/bin")
if not os.path.exists("build/linux/usr/share"):
    os.mkdir("build/linux/usr/share")
if not os.path.exists("build/linux/usr/share/man"):
    os.mkdir("build/linux/usr/share/man")
if not os.path.exists("build/linux/usr/share/man/man1"):
    os.mkdir("build/linux/usr/share/man/man1")

# Limpa diretórios anteriores
if os.path.exists("dist"):
    shutil.rmtree("dist")

print("Criando executável standalone para Linux...")
subprocess.call([
    "pyinstaller",
    "--onefile",
    "--name", "voidbound",
    "cryptoservice.py"
])

# Copiar executável para estrutura de pacote .deb
shutil.copy("dist/voidbound", "build/linux/usr/bin/")
os.chmod("build/linux/usr/bin/voidbound", 0o755)

# Criar arquivo de controle para pacote .deb
control = """Package: voidbound
Version: 1.0.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: VoidBound Team <voidbound@example.com>
Description: Serviço de Criptografia/Descriptografia de Arquivos
 VoidBound é um serviço de criptografia e descriptografia
 de arquivos usando AES-256 em modo CBC com preenchimento PKCS7.
 .
 Características:
  * Criptografia AES-256 em modo CBC
  * Derivação de chave segura com PBKDF2
  * Processamento de arquivos em blocos para suporte a arquivos grandes
  * Interface de linha de comando intuitiva
"""

with open("build/linux/DEBIAN/control", "w") as f:
    f.write(control)

# Criar manual page
manpage = """.TH VOIDBOUND 1 "Abril 2025" "VoidBound 1.0.0" "Utilitários de Segurança"
.SH NOME
voidbound \- criptografia e descriptografia de arquivos com AES-256
.SH SINOPSE
.B voidbound
[OPÇÕES]
.SH DESCRIÇÃO
.B VoidBound
é uma ferramenta para criptografar e descriptografar arquivos
usando algoritmo AES-256 em modo CBC com preenchimento PKCS7.
.SH OPÇÕES
.TP
.B \-\-encrypt, \-e
Modo de criptografia.
.TP
.B \-\-decrypt, \-d
Modo de descriptografia.
.TP
.B \-\-input PATH, \-i PATH
Caminho do arquivo ou diretório para processar.
.TP
.B \-\-password PASSWORD, \-p PASSWORD
Senha para criptografia/descriptografia (omitir para prompt seguro).
.TP
.B \-\-output DIR, \-o DIR
Diretório de saída (opcional).
.TP
.B \-\-verbose, \-v
Exibir informações detalhadas de processamento.
.SH EXEMPLOS
.TP
Criptografar um arquivo:
voidbound --encrypt --input arquivo.txt
.TP
Descriptografar um arquivo:
voidbound --decrypt --input arquivo.txt.encrypted
.TP
Criptografar um diretório:
voidbound --encrypt --input /pasta --output /destino
.SH AVISO
Não há como recuperar arquivos se a senha for perdida!
"""

with open("build/linux/usr/share/man/man1/voidbound.1", "w") as f:
    f.write(manpage)

# Criar script de pós-instalação
postinst = """#!/bin/bash
# Compress manpage
gzip -9 /usr/share/man/man1/voidbound.1
# Create symlink for easy access
ln -sf /usr/bin/voidbound /usr/bin/vcodex
"""

with open("build/linux/DEBIAN/postinst", "w") as f:
    f.write(postinst)
os.chmod("build/linux/DEBIAN/postinst", 0o755)

# Criar script de instalação para distribuições sem dpkg
install_script = """#!/bin/bash

# Script de instalação VoidBound para Linux
echo "Instalando VoidBound..."

# Verificar privilégios de administrador
if [ "$(id -u)" != "0" ]; then
   echo "Este script precisa ser executado como root" 1>&2
   exit 1
fi

# Copiar executável para /usr/local/bin
cp voidbound /usr/local/bin/
chmod +x /usr/local/bin/voidbound

# Criar link simbólico para fácil acesso
ln -sf /usr/local/bin/voidbound /usr/local/bin/vcodex

echo "Instalação concluída. Execute 'voidbound --help' para ver as opções de uso."
"""

with open("build/install.sh", "w") as f:
    f.write(install_script)
os.chmod("build/install.sh", 0o755)

# Criar script de desinstalação
uninstall_script = """#!/bin/bash

# Script de desinstalação VoidBound para Linux
echo "Desinstalando VoidBound..."

# Verificar privilégios de administrador
if [ "$(id -u)" != "0" ]; then
   echo "Este script precisa ser executado como root" 1>&2
   exit 1
fi

# Remover executável
rm -f /usr/local/bin/voidbound
rm -f /usr/local/bin/vcodex

echo "VoidBound desinstalado com sucesso."
"""

with open("build/uninstall.sh", "w") as f:
    f.write(uninstall_script)
os.chmod("build/uninstall.sh", 0o755)

# Cópia do executável para distribuição standalone
shutil.copy("dist/voidbound", "build/")

# Criar pacote .deb
print("Criando pacote .deb...")
subprocess.call([
    "dpkg-deb",
    "--build",
    "build/linux",
    "build/voidbound_1.0.0_amd64.deb"
])

# Criar arquivo tar.gz para distribuições sem dpkg
print("Criando pacote tar.gz...")
subprocess.call([
    "tar", 
    "-czf", 
    "build/VoidBound-Linux.tar.gz", 
    "-C", "build", 
    "voidbound", 
    "install.sh", 
    "uninstall.sh"
])

# Criar arquivo README para distribuição
readme = """# VoidBound - Linux (CLI)

VoidBound é um serviço de criptografia e descriptografia de arquivos utilizando AES-256 em modo CBC.

## Instalação

### Para sistemas Debian/Ubuntu:


sudo dpkg -i voidbound_1.0.0_amd64.deb


Se houver dependências faltantes:

sudo apt-get install -f


### Para outras distribuições Linux:

1. Extraia o arquivo tar.gz:
   
   tar -xzf VoidBound-Linux.tar.gz
   

2. Execute o instalador:
   
   sudo ./install.sh
   

## Uso


# Ver ajuda e opções disponíveis
voidbound --help

# Criptografar um arquivo
voidbound --encrypt --input arquivo.txt

# Descriptografar um arquivo
voidbound --decrypt --input arquivo.txt.encrypted

# Criptografar um diretório inteiro
voidbound --encrypt --input /caminho/pasta --output /destino


Você também pode usar o comando abreviado `vcodex` em vez de `voidbound`.

## Desinstalação

### Para sistemas Debian/Ubuntu:

sudo apt remove voidbound


### Para outras distribuições Linux:

sudo ./uninstall.sh


## Observação importante
NUNCA perca sua senha! Arquivos criptografados não podem ser recuperados sem a senha correta.
"""

with open("build/README.md", "w") as f:
    f.write(readme)

print("\nProcesso concluído!")
print("Os seguintes arquivos foram criados:")
print("- build/voidbound_1.0.0_amd64.deb (para sistemas baseados em Debian/Ubuntu)")
print("- build/VoidBound-Linux.tar.gz (para outras distribuições Linux)")
print("- build/voidbound (executável standalone)")
