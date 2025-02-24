import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ChatApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Chat LAN")
        
        # Configuración del socket
        self.HOST = socket.gethostbyname(socket.gethostname())
        self.PORT = 5000
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Añadir nickname
        self.nickname = ""
        self.nickname_frame = tk.Frame(self.window)
        self.nickname_frame.pack(padx=10, pady=5)
        
        self.nickname_entry = tk.Entry(self.nickname_frame, width=15)
        self.nickname_entry.insert(0, "Tu nickname")
        self.nickname_entry.pack(side=tk.LEFT, padx=5)
        
        self.nickname_button = tk.Button(self.nickname_frame, text="Guardar Nick", command=self.set_nickname)
        self.nickname_button.pack(side=tk.LEFT)
        
        # Configuración del cifrado
        password = "ChatSecureKey2024"  # Clave maestra para generar la clave de cifrado
        salt = b'salt_'  # Salt para el KDF
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)
        
        # Interfaz gráfica
        self.chat_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, width=40, height=20)
        self.chat_area.pack(padx=10, pady=10)
        
        self.msg_entry = tk.Entry(self.window, width=30)
        self.msg_entry.pack(padx=10, pady=5)
        
        self.dest_ip = tk.Entry(self.window, width=15)
        self.dest_ip.insert(0, "IP destino")
        self.dest_ip.pack(padx=10, pady=5)
        
        self.send_button = tk.Button(self.window, text="Enviar", command=self.send_message)
        self.send_button.pack(padx=10, pady=5)
        
        # Iniciar servidor
        try:
            self.socket.bind((self.HOST, self.PORT))
            self.socket.listen()
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.chat_area.insert(tk.END, f"Servidor iniciado en {self.HOST}:{self.PORT}\n")
        except:
            messagebox.showerror("Error", "No se pudo iniciar el servidor")
            
    def set_nickname(self):
        self.nickname = self.nickname_entry.get()
        self.nickname_entry.config(state='disabled')
        self.nickname_button.config(state='disabled')
        messagebox.showinfo("Éxito", f"Nickname establecido como: {self.nickname}")

    def send_message(self):
        try:
            dest_ip = self.dest_ip.get()
            message = self.msg_entry.get()
            if message and dest_ip and self.nickname:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((dest_ip, self.PORT))
                # Usar nickname en lugar de HOST
                encrypted_message = self.cipher_suite.encrypt(f"{self.nickname}: {message}".encode())
                client.send(encrypted_message)
                client.close()
                self.chat_area.insert(tk.END, f"Tú: {message}\n")
                self.msg_entry.delete(0, tk.END)
            elif not self.nickname:
                messagebox.showerror("Error", "Por favor establece un nickname primero")
        except:
            messagebox.showerror("Error", "No se pudo enviar el mensaje")
            
    def receive_messages(self):
        while True:
            try:
                client, address = self.socket.accept()
                encrypted_message = client.recv(1024)
                # Descifrar el mensaje recibido
                decrypted_message = self.cipher_suite.decrypt(encrypted_message).decode()
                self.chat_area.insert(tk.END, f"{decrypted_message}\n")
                client.close()
            except Exception as e:
                print(f"Error al recibir mensaje: {e}")
                break
                
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = ChatApp()
    app.run()
