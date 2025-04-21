import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
from voidbound.file_handler import FileHandler

class VoidBoundGUI:
    def __init__(self, root):
        self.root = root
        root.title("VoidBound - Criptografia de Arquivos")
        root.geometry("600x400")
        root.resizable(True, True)
        
        # Configurar estilo
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('TLabel', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        
        # Frame principal
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        ttk.Label(main_frame, text="VoidBound - Serviço de Criptografia de Arquivos", 
                  style='Header.TLabel').grid(column=0, row=0, columnspan=3, pady=10, sticky=tk.W)
        
        # Modo
        ttk.Label(main_frame, text="Modo:").grid(column=0, row=1, sticky=tk.W, pady=5)
        self.mode_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(main_frame, text="Criptografar", value="encrypt", 
                       variable=self.mode_var).grid(column=1, row=1, sticky=tk.W)
        ttk.Radiobutton(main_frame, text="Descriptografar", value="decrypt", 
                       variable=self.mode_var).grid(column=2, row=1, sticky=tk.W)
        
        # Caminho de entrada
        ttk.Label(main_frame, text="Arquivo/Pasta:").grid(column=0, row=2, sticky=tk.W, pady=5)
        self.input_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.input_var, width=50).grid(column=1, row=2, sticky=(tk.W, tk.E))
        ttk.Button(main_frame, text="Navegar", command=self.browse_input).grid(column=2, row=2, padx=5)
        
        # Pasta de saída
        ttk.Label(main_frame, text="Pasta de Saída:").grid(column=0, row=3, sticky=tk.W, pady=5)
        self.output_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.output_var, width=50).grid(column=1, row=3, sticky=(tk.W, tk.E))
        ttk.Button(main_frame, text="Navegar", command=self.browse_output).grid(column=2, row=3, padx=5)
        
        # Senha
        ttk.Label(main_frame, text="Senha:").grid(column=0, row=4, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=50)
        self.password_entry.grid(column=1, row=4, sticky=(tk.W, tk.E))
        
        # Confirmar senha
        ttk.Label(main_frame, text="Confirmar Senha:").grid(column=0, row=5, sticky=tk.W, pady=5)
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(main_frame, textvariable=self.confirm_var, show="*", width=50)
        self.confirm_entry.grid(column=1, row=5, sticky=(tk.W, tk.E))
        
        # Opção verboso
        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Modo detalhado", variable=self.verbose_var).grid(
            column=0, row=6, columnspan=2, sticky=tk.W, pady=5)
        
        # Barra de progresso
        self.progress = ttk.Progressbar(main_frame, orient="horizontal", mode="indeterminate")
        self.progress.grid(column=0, row=7, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Status
        self.status_var = tk.StringVar(value="Pronto para iniciar.")
        ttk.Label(main_frame, textvariable=self.status_var).grid(
            column=0, row=8, columnspan=3, sticky=tk.W, pady=5)
        
        # Botões
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(column=0, row=9, columnspan=3, pady=10)
        
        ttk.Button(button_frame, text="Executar", command=self.process).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Sair", command=root.destroy).pack(side=tk.LEFT, padx=5)
        
        # Configurar o grid
        for i in range(10):
            main_frame.rowconfigure(i, weight=1)
        main_frame.columnconfigure(1, weight=1)
    
    def browse_input(self):
        """Navegar para selecionar arquivo ou pasta de entrada."""
        path = filedialog.askdirectory() if messagebox.askyesno(
            "Selecionar", "Deseja selecionar uma pasta?\n(Escolha 'Não' para selecionar um arquivo)"
        ) else filedialog.askopenfilename()
        
        if path:
            self.input_var.set(path)
    
    def browse_output(self):
        """Navegar para selecionar pasta de saída."""
        path = filedialog.askdirectory()
        if path:
            self.output_var.set(path)
    
    def validate_inputs(self):
        """Validar entradas do usuário."""
        # Verificar caminho de entrada
        if not self.input_var.get():
            messagebox.showerror("Erro", "Por favor selecione um arquivo ou pasta de entrada.")
            return False
        
        if not os.path.exists(self.input_var.get()):
            messagebox.showerror("Erro", "O caminho de entrada não existe.")
            return False
        
        # Verificar pasta de saída se fornecida
        if self.output_var.get() and not os.path.isdir(self.output_var.get()):
            messagebox.showerror("Erro", "A pasta de saída não existe.")
            return False
        
        # Verificar senha
        if not self.password_var.get():
            messagebox.showerror("Erro", "Por favor digite uma senha.")
            return False
        
        # Verificar confirmação de senha
        if self.password_var.get() != self.confirm_var.get():
            messagebox.showerror("Erro", "As senhas não correspondem.")
            return False
        
        return True
    
    def process(self):
        """Iniciar o processamento em uma thread separada."""
        if not self.validate_inputs():
            return
        
        # Iniciar indicador de progresso
        self.progress.start()
        self.status_var.set("Processando...")
        
        # Desabilitar botões durante o processamento
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.configure(state="disabled")
        
        # Iniciar em thread separada para não bloquear a GUI
        threading.Thread(target=self._process_thread, daemon=True).start()
    
    def _process_thread(self):
        """Executa o processamento em thread separada."""
        try:
            # Obter parâmetros
            encrypt = self.mode_var.get() == "encrypt"
            input_path = self.input_var.get()
            output_dir = self.output_var.get() if self.output_var.get() else None
            password = self.password_var.get()
            verbose = self.verbose_var.get()
            
            # Processar
            processed_files = FileHandler.process_path(
                input_path, password, encrypt, output_dir, verbose
            )
            
            # Atualizar GUI no thread principal
            self.root.after(0, self._process_complete, processed_files)
        
        except Exception as e:
            # Mostrar erro
            self.root.after(0, self._process_error, str(e))
    
    def _process_complete(self, processed_files):
        """Chamado quando o processamento é concluído com sucesso."""
        # Parar indicador de progresso
        self.progress.stop()
        
        # Reabilitar botões
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.configure(state="normal")
        
        # Atualizar status
        mode = "criptografados" if self.mode_var.get() == "encrypt" else "descriptografados"
        self.status_var.set(f"Concluído: {len(processed_files)} arquivos {mode}.")
        
        # Mostrar mensagem de sucesso
        messagebox.showinfo("Sucesso", f"{len(processed_files)} arquivos foram {mode} com sucesso.")
    
    def _process_error(self, error_msg):
        """Chamado quando ocorre um erro durante o processamento."""
        # Parar indicador de progresso
        self.progress.stop()
        
        # Reabilitar botões
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.configure(state="normal")
        
        # Atualizar status
        self.status_var.set(f"Erro: {error_msg}")
        
        # Mostrar mensagem de erro
        messagebox.showerror("Erro", f"Ocorreu um erro: {error_msg}")

def main():
    root = tk.Tk()
    app = VoidBoundGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()