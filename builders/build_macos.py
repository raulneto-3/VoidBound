import os
import sys
import subprocess
import shutil
import platform

# Verifica se estamos no macOS
if platform.system() != "Darwin":
    print("Este script deve ser executado no macOS.")
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

# Limpa diretórios anteriores
if os.path.exists("dist"):
    shutil.rmtree("dist")

# Cria um arquivo de ícone (opcional)
if not os.path.exists("resources"):
    os.mkdir("resources")

print("Criando aplicativo macOS...")
subprocess.call([
    "pyinstaller",
    "--onefile",
    "--name", "voidbound",
    "cryptoservice.py"
])

# Criar script de instalação
install_script = """#!/bin/bash

# Script de instalação VoidBound para macOS
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

echo "Instalação concluída. Execute 'voidbound' ou 'vcodex' para usar o aplicativo."
"""

# Salvar script de instalação
with open("build/install.sh", "w") as f:
    f.write(install_script)
os.chmod("build/install.sh", 0o755)

# Criar script de desinstalação
uninstall_script = """#!/bin/bash

# Script de desinstalação VoidBound para macOS
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

# Salvar script de desinstalação
with open("build/uninstall.sh", "w") as f:
    f.write(uninstall_script)
os.chmod("build/uninstall.sh", 0o755)

# Preparar pacote final
shutil.copy("dist/voidbound", "build/")

# Criar arquivo README para o instalador
readme = """# VoidBound - macOS

## Instalação

1. Abra o Terminal
2. Navegue até esta pasta: `cd /caminho/para/esta/pasta`
3. Execute o instalador: `sudo ./install.sh`

## Uso

- Execute `voidbound -h` para ver as opções de uso
- Você também pode usar o comando abreviado `vcodex`

## Desinstalação

- Execute `sudo ./uninstall.sh` para remover o aplicativo
"""

with open("build/README.md", "w") as f:
    f.write(readme)

# Criar arquivo tar.gz para distribuição
print("Criando pacote tar.gz...")
subprocess.call([
    "tar", 
    "-czf", 
    "build/VoidBound-macOS.tar.gz", 
    "-C", "build", 
    "voidbound", 
    "install.sh", 
    "uninstall.sh", 
    "README.md"
])

print("Processo concluído!")
print("O pacote de instalação está disponível em: build/VoidBound-macOS.tar.gz")