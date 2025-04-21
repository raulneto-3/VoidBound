import os
import sys
import subprocess
import shutil

# Verifica se PyInstaller está instalado
try:
    import PyInstaller
except ImportError:
    print("Instalando PyInstaller...")
    subprocess.call([sys.executable, "-m", "pip", "install", "pyinstaller"])

# Verifica se NSIS está instalado (para criação do instalador)
nsis_path = r"C:\Program Files (x86)\NSIS\makensis.exe"
if not os.path.exists(nsis_path):
    print("AVISO: NSIS não encontrado. O instalador não será criado.")
    print("Baixe e instale NSIS de http://nsis.sourceforge.net/Download")
    nsis_available = False
else:
    nsis_available = True

# Cria pasta de build se não existir
if not os.path.exists("build"):
    os.mkdir("build")

# Limpa diretórios anteriores
if os.path.exists("dist"):
    shutil.rmtree("dist")

print("Criando executável standalone para CLI...")
subprocess.call([
    "pyinstaller",
    "--onefile",
    "--name", "voidbound-cli",
    "--icon=resources/icon.ico",  # Adicione um ícone ao projeto
    "cryptoservice.py"
])

print("Criando executável standalone para GUI...")
subprocess.call([
    "pyinstaller",
    "--onefile", 
    "--windowed",
    "--name", "voidbound-gui",
    "--icon=resources/icon.ico",  # Adicione um ícone ao projeto
    "gui.py"
])

# Copiar executáveis para pasta de build
shutil.copy("dist/voidbound-cli.exe", "build/")
shutil.copy("dist/voidbound-gui.exe", "build/")

# Criar arquivo NSIS para o instalador
nsis_script = r"""
!include "MUI2.nsh"
!include "FileFunc.nsh"

; Nome do instalador
Name "VoidBound"
OutFile "VoidBound-Setup.exe"

; Diretório de instalação padrão
InstallDir "$PROGRAMFILES\VoidBound"

; Solicitar privilégios de administrador
RequestExecutionLevel admin

; Interface
!define MUI_ABORTWARNING
!define MUI_ICON "resources\icon.ico"

; Páginas
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Idiomas
!insertmacro MUI_LANGUAGE "Portuguese"

Section "Programa Principal" SecMain
    SetOutPath "$INSTDIR"
    
    ; Arquivos a serem instalados
    File "build\voidbound-cli.exe"
    File "build\voidbound-gui.exe"
    File "resources\icon.ico"
    
    ; Criar atalhos
    CreateDirectory "$SMPROGRAMS\VoidBound"
    CreateShortcut "$SMPROGRAMS\VoidBound\VoidBound.lnk" "$INSTDIR\voidbound-gui.exe" "" "$INSTDIR\icon.ico"
    CreateShortcut "$DESKTOP\VoidBound.lnk" "$INSTDIR\voidbound-gui.exe" "" "$INSTDIR\icon.ico"
    
    ; Adicionar ao PATH
    EnVar::SetHKLM
    EnVar::AddValue "PATH" "$INSTDIR"
    
    ; Criar entrada de desinstalação
    WriteUninstaller "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoidBound" "DisplayName" "VoidBound"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoidBound" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoidBound" "DisplayIcon" "$INSTDIR\icon.ico"
SectionEnd

Section "Uninstall"
    ; Remover arquivos
    Delete "$INSTDIR\voidbound-cli.exe"
    Delete "$INSTDIR\voidbound-gui.exe"
    Delete "$INSTDIR\icon.ico"
    Delete "$INSTDIR\uninstall.exe"
    
    ; Remover diretórios
    RMDir "$INSTDIR"
    Delete "$SMPROGRAMS\VoidBound\VoidBound.lnk"
    RMDir "$SMPROGRAMS\VoidBound"
    Delete "$DESKTOP\VoidBound.lnk"
    
    ; Remover registro
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VoidBound"
    
    ; Tentar remover do PATH (opcional)
    EnVar::SetHKLM
    EnVar::DeleteValue "PATH" "$INSTDIR"
SectionEnd
"""

# Salvar script NSIS
with open("build/installer.nsi", "w") as f:
    f.write(nsis_script)

# Executar NSIS para criar o instalador
if nsis_available:
    print("Criando instalador Windows...")
    subprocess.call([nsis_path, "build/installer.nsi"])
    
    # Mover o instalador para a pasta build
    shutil.move("VoidBound-Setup.exe", "build/VoidBound-Setup.exe")
    print("Instalador criado com sucesso: build/VoidBound-Setup.exe")
else:
    print("Executáveis standalone criados: build/voidbound-cli.exe e build/voidbound-gui.exe")

print("Processo concluído!")