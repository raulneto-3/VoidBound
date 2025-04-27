import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_nsis_installation():
    """Check for NSIS installation in different possible locations"""
    possible_paths = [
        r"D:\Dev\NSIS\makensis.exe",
        r"D:\Dev\NSIS\makensis.exe",
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return None

def check_conda_env():
    """Check if running in a Conda environment and warn about potential issues"""
    if os.environ.get('CONDA_PREFIX') is not None:
        print("AVISO: Executando em ambiente Conda. Isso pode causar problemas com PyInstaller.")
        print("Considere usar uma instalação Python padrão para criar os executáveis.")
        print("Tentando instalar dependências necessárias...\n")
        # Try installing pyexpat equivalent in conda
        try:
            subprocess.call([sys.executable, "-m", "conda", "install", "-y", "pywin32"])
            subprocess.call([sys.executable, "-m", "pip", "install", "pywin32"])
            return True
        except:
            return False
    return True

# Get the project root directory
project_root = Path(__file__).parent.parent
os.chdir(project_root)

# Check for conda environment issues
conda_ok = check_conda_env()

# Verify if PyInstaller is installed
try:
    import PyInstaller
except ImportError:
    print("Instalando PyInstaller...")
    subprocess.call([sys.executable, "-m", "pip", "install", "pyinstaller"])

# Check NSIS availability
nsis_path = check_nsis_installation()
if nsis_path:
    nsis_available = True
    # Check for EnVar plugin
    nsis_plugins_dir = os.path.dirname(nsis_path) + r"\Plugins"
    if not (os.path.exists(nsis_plugins_dir + r"\x86-ansi\EnVar.dll") or 
            os.path.exists(nsis_plugins_dir + r"\EnVar.dll")):
        print("AVISO: Plugin EnVar não encontrado. Instalador será criado sem modificação PATH.")
        use_envar = False
    else:
        use_envar = True
else:
    print("AVISO: NSIS não encontrado. O instalador não será criado.")
    print("Baixe e instale NSIS de http://nsis.sourceforge.net/Download")
    nsis_available = False
    use_envar = False

# Verify icon existence
icon_path = os.path.join(project_root, "assets", "icon.ico")
if not os.path.exists(icon_path):
    print(f"AVISO: Ícone não encontrado em {icon_path}")
    print("Criando executáveis sem ícone personalizado.")
    icon_option = []
    has_icon = False
else:
    icon_option = ["--icon", icon_path]
    has_icon = True

# Create build folder if it doesn't exist
build_dir = os.path.join(project_root, "build")
if not os.path.exists(build_dir):
    os.makedirs(build_dir)

# Clean previous build files
dist_dir = os.path.join(project_root, "dist")
if os.path.exists(dist_dir):
    shutil.rmtree(dist_dir)

# Define envar include string outside of f-string to avoid backslash issue
envar_include = '!include "EnVar.nsh"' if use_envar else ''

# Define PATH modification strings outside of f-string
if use_envar:
    envar_add_code = """
    EnVar::SetHKLM
    EnVar::AddValue "PATH" "$INSTDIR"
    """
    envar_remove_code = """
    EnVar::SetHKLM
    EnVar::DeleteValue "PATH" "$INSTDIR"
    """
else:
    envar_add_code = '; PATH modification requires EnVar plugin'
    envar_remove_code = '; PATH modification requires EnVar plugin'

if conda_ok:
    try:
        print("Instalando dependências necessárias...")
        # Install all dependencies from requirements.txt
        subprocess.call([sys.executable, "-m", "pip", "install", "-r", 
                         os.path.join(project_root, "requirements.txt")])
        
        # Additional dependencies for PyInstaller
        subprocess.call([sys.executable, "-m", "pip", "install", "pywin32"])
        
        print("Criando executável standalone para CLI...")
        cli_result = subprocess.run([
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--name", "voidbound-cli",
            "--hidden-import", "cryptography",
            "--hidden-import", "cryptography.hazmat.primitives",
            "--hidden-import", "cryptography.hazmat.primitives.ciphers",
            "--hidden-import", "cryptography.hazmat.primitives.asymmetric",
            "--hidden-import", "cryptography.hazmat.backends",
            "--hidden-import", "argon2",
            "--hidden-import", "argon2_cffi",
            "--hidden-import", "Crypto",
            "--hidden-import", "Crypto.Cipher",
            "--hidden-import", "tqdm",
            "--hidden-import", "typing",
            "--hidden-import", "typing.Generator",
            *icon_option,
            os.path.join(project_root, "cryptoservice.py")
        ], check=False)

        print("Criando executável standalone para GUI...")
        gui_result = subprocess.run([
            sys.executable, "-m", "PyInstaller",
            "--onefile", 
            "--windowed",
            "--name", "voidbound-gui",
            "--hidden-import", "cryptography",
            "--hidden-import", "cryptography.hazmat.primitives",
            "--hidden-import", "cryptography.hazmat.primitives.ciphers",
            "--hidden-import", "cryptography.hazmat.primitives.asymmetric",
            "--hidden-import", "cryptography.hazmat.backends",
            "--hidden-import", "argon2",
            "--hidden-import", "argon2_cffi",
            "--hidden-import", "Crypto",
            "--hidden-import", "Crypto.Cipher",
            "--hidden-import", "tqdm",
            "--hidden-import", "typing",
            "--hidden-import", "typing.Generator",
            *icon_option,
            os.path.join(project_root, "voidbound", "gui.py")
        ], check=False)
    except Exception as e:
        print(f"ERRO ao criar executáveis: {str(e)}")
        sys.exit(1)
else:
    print("Pulando criação de executáveis devido a problemas com o ambiente Conda.")
    sys.exit(1)

# Check if executables were created successfully
cli_exec = os.path.join(dist_dir, "voidbound-cli.exe")
gui_exec = os.path.join(dist_dir, "voidbound-gui.exe")
cli_success = os.path.exists(cli_exec)
gui_success = os.path.exists(gui_exec)

# Copy executables to the build folder
if cli_success:
    shutil.copy(cli_exec, build_dir)
    print(f"CLI executável copiado para {build_dir}")
else:
    print("ERRO: voidbound-cli.exe não foi criado com sucesso.")

if gui_success:
    shutil.copy(gui_exec, build_dir)
    print(f"GUI executável copiado para {build_dir}")
else:
    print("ERRO: voidbound-gui.exe não foi criado com sucesso.")

if not (cli_success and gui_success):
    print("Falha na criação dos executáveis. Abortando.")
    sys.exit(1)

# Create batch file for command line access
print("Criando arquivo batch para acesso via linha de comando...")
batch_file_path = os.path.join(build_dir, "voidbound.bat")
with open(batch_file_path, "w") as f:
    f.write('@echo off\n"%~dp0voidbound-cli.exe" %*')

# Construir o script NSIS em partes para evitar problemas com f-strings e backslashes
header = """
!include "MUI2.nsh"
!include "FileFunc.nsh"
""" + envar_include + """

; Nome do instalador
Name "VoidBound"
OutFile "VoidBound-Setup.exe"

; Diretório de instalação padrão
InstallDir "$PROGRAMFILES\\VoidBound"

; Solicitar privilégios de administrador
RequestExecutionLevel admin

; Interface
!define MUI_ABORTWARNING
"""

# Adicionar o ícone se disponível
if has_icon:
    header += f'!define MUI_ICON "{icon_path}"\n'

# Continuar com o resto do script
middle = """
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
"""

# Adicionar arquivos
files = f'    File "{os.path.join(build_dir, "voidbound-cli.exe")}"\n'
files += f'    File "{os.path.join(build_dir, "voidbound-gui.exe")}"\n'
files += f'    File "{batch_file_path}"\n'
if has_icon:
    files += f'    File "{icon_path}"\n'

# Adicionar atalhos
shortcuts = """
    ; Criar atalhos
    CreateDirectory "$SMPROGRAMS\\VoidBound"
"""

if has_icon:
    shortcuts += '    CreateShortcut "$SMPROGRAMS\\VoidBound\\VoidBound.lnk" "$INSTDIR\\voidbound-gui.exe" "" "$INSTDIR\\icon.ico"\n'
    shortcuts += '    CreateShortcut "$DESKTOP\\VoidBound.lnk" "$INSTDIR\\voidbound-gui.exe" "" "$INSTDIR\\icon.ico"\n'
else:
    shortcuts += '    CreateShortcut "$SMPROGRAMS\\VoidBound\\VoidBound.lnk" "$INSTDIR\\voidbound-gui.exe" "" ""\n'
    shortcuts += '    CreateShortcut "$DESKTOP\\VoidBound.lnk" "$INSTDIR\\voidbound-gui.exe" "" ""\n'

# Adicionar PATH e entrada de desinstalação
path_and_uninstall = """
    ; Adicionar ao PATH
""" + envar_add_code + """
    
    ; Criar entrada de desinstalação
    WriteUninstaller "$INSTDIR\\uninstall.exe"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VoidBound" "DisplayName" "VoidBound"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VoidBound" "UninstallString" "$\\"$INSTDIR\\uninstall.exe$\\""
"""

if has_icon:
    path_and_uninstall += '    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VoidBound" "DisplayIcon" "$INSTDIR\\icon.ico"\n'

# Seção de desinstalação
uninstall_section = """
SectionEnd

Section "Uninstall"
    ; Remover arquivos
    Delete "$INSTDIR\\voidbound-cli.exe"
    Delete "$INSTDIR\\voidbound-gui.exe"
"""

if has_icon:
    uninstall_section += '    Delete "$INSTDIR\\icon.ico"\n'

uninstall_section += """
    Delete "$INSTDIR\\uninstall.exe"
    
    ; Remover diretórios
    RMDir "$INSTDIR"
    Delete "$SMPROGRAMS\\VoidBound\\VoidBound.lnk"
    RMDir "$SMPROGRAMS\\VoidBound"
    Delete "$DESKTOP\\VoidBound.lnk"
    
    ; Remover registro
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VoidBound"
    
    ; Tentar remover do PATH (opcional)
""" + envar_remove_code + """
SectionEnd
"""

# Combinando todas as partes
nsis_script = header + middle + files + shortcuts + path_and_uninstall + uninstall_section

# Save NSIS script
nsis_script_path = os.path.join(build_dir, "installer.nsi")
with open(nsis_script_path, "w") as f:
    f.write(nsis_script)

# Create installer if NSIS is available
if nsis_available:
    print("Criando instalador Windows...")
    try:
        subprocess.run([nsis_path, nsis_script_path], check=True)
        
        # Move installer to build folder
        installer_path = os.path.join(project_root, "VoidBound-Setup.exe")
        if os.path.exists(installer_path):
            shutil.move(installer_path, os.path.join(build_dir, "VoidBound-Setup.exe"))
            print(f"Instalador criado com sucesso: {os.path.join(build_dir, 'VoidBound-Setup.exe')}")
        else:
            print("ERRO: O instalador não foi criado corretamente.")
    except subprocess.CalledProcessError:
        print("ERRO: Falha ao criar o instalador NSIS.")
else:
    print(f"Executáveis standalone criados: {build_dir}/voidbound-cli.exe e {build_dir}/voidbound-gui.exe")

# Clean up unnecessary files after build
print("Limpando arquivos temporários...")

# Remove PyInstaller build directory
pyinstaller_build_dir = os.path.join(project_root, "build", "voidbound-cli")
if os.path.exists(pyinstaller_build_dir):
    shutil.rmtree(pyinstaller_build_dir)

pyinstaller_build_dir = os.path.join(project_root, "build", "voidbound-gui")
if os.path.exists(pyinstaller_build_dir):
    shutil.rmtree(pyinstaller_build_dir)

# Remove dist directory if it exists
if os.path.exists(dist_dir):
    shutil.rmtree(dist_dir)

# Remove spec files
for spec_file in ["voidbound-cli.spec", "voidbound-gui.spec"]:
    spec_path = os.path.join(project_root, spec_file)
    if os.path.exists(spec_path):
        os.remove(spec_path)
        print(f"Removido: {spec_file}")

# Remove temporary NSIS script if installer was created successfully
# if nsis_available and os.path.exists(os.path.join(build_dir, "VoidBound-Setup.exe")):
#     os.remove(nsis_script_path)
#     print(f"Removido: {os.path.basename(nsis_script_path)}")

print("Limpeza concluída!")

print("Processo concluído!")