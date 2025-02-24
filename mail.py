import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, Canvas
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import os
import time

class ChatApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Chat LAN")
        
        # Configuración del socket
        self.HOST = socket.gethostbyname(socket.gethostname())
        self.PORT = 5000
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Configurar directorio de datos
        self.data_dir = "Simple-Lan-Mail/datos"
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        
        # Configurar archivos de datos
        self.ips_file = os.path.join(self.data_dir, "saved_ips.json")
        self.nickname_file = os.path.join(self.data_dir, "nickname.json")
        
        self.saved_ips = self.load_saved_ips()
        self.nickname = self.load_nickname()
        
        # Añadir nickname
        self.nickname_frame = tk.Frame(self.window)
        self.nickname_frame.pack(padx=10, pady=5)
        
        self.nickname_entry = tk.Entry(self.nickname_frame, width=15)
        if self.nickname:
            self.nickname_entry.insert(0, self.nickname)
            self.nickname_entry.config(state='disabled')
        else:
            self.nickname_entry.insert(0, "Tu nickname")
        self.nickname_entry.pack(side=tk.LEFT, padx=5)
        
        self.nickname_button = tk.Button(self.nickname_frame, text="Guardar Nick", command=self.set_nickname)
        if self.nickname:
            self.nickname_button.config(state='disabled')
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
        
        # Frame para IP
        self.ip_frame = tk.Frame(self.window)
        self.ip_frame.pack(padx=10, pady=5)
        
        # Combobox para IPs guardadas
        self.ip_combo = ttk.Combobox(self.ip_frame, width=15, values=list(self.saved_ips))
        self.ip_combo.pack(side=tk.LEFT, padx=5)
        self.ip_combo.set("Selecciona IP")
        
        # Entry para nueva IP
        self.dest_ip = tk.Entry(self.ip_frame, width=15)
        self.dest_ip.insert(0, "Nueva IP")
        self.dest_ip.pack(side=tk.LEFT, padx=5)
        
        self.send_button = tk.Button(self.window, text="Enviar", command=self.send_message)
        self.send_button.pack(padx=10, pady=5)
        
        # Indicador de conexión
        self.connection_frame = tk.Frame(self.window)
        self.connection_frame.pack(padx=10, pady=5)
        
        self.connection_canvas = Canvas(self.connection_frame, width=20, height=20)
        self.connection_canvas.pack(side=tk.LEFT)
        self.led = self.connection_canvas.create_oval(5, 5, 15, 15, fill='red')
        
        self.connection_label = tk.Label(self.connection_frame, text="Sin conexión")
        self.connection_label.pack(side=tk.LEFT, padx=5)
        
        # Iniciar verificación de conexión
        self.last_connection_check = 0
        self.check_interval = 5  # segundos
        threading.Thread(target=self.connection_checker, daemon=True).start()
        
        # Iniciar servidor
        try:
            self.socket.bind((self.HOST, self.PORT))
            self.socket.listen()
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.chat_area.insert(tk.END, f"Servidor iniciado en {self.HOST}:{self.PORT}\n")
        except:
            messagebox.showerror("Error", "No se pudo iniciar el servidor")
            
    def load_saved_ips(self):
        if os.path.exists(self.ips_file):
            try:
                with open(self.ips_file, 'r') as f:
                    return set(json.load(f))
            except:
                return set()
        return set()

    def save_ip(self, ip):
        if ip not in self.saved_ips:
            self.saved_ips.add(ip)
            try:
                with open(self.ips_file, 'w') as f:
                    json.dump(list(self.saved_ips), f)
                self.ip_combo['values'] = list(self.saved_ips)
            except:
                messagebox.showerror("Error", "No se pudo guardar la IP")

    def load_nickname(self):
        if os.path.exists(self.nickname_file):
            try:
                with open(self.nickname_file, 'r') as f:
                    data = json.load(f)
                    return data.get('nickname', '')
            except:
                return ''
        return ''

    def set_nickname(self):
        self.nickname = self.nickname_entry.get()
        self.nickname_entry.config(state='disabled')
        self.nickname_button.config(state='disabled')
        
        # Guardar nickname
        try:
            with open(self.nickname_file, 'w') as f:
                json.dump({'nickname': self.nickname}, f)
            messagebox.showinfo("Éxito", f"Nickname establecido como: {self.nickname}")
        except:
            messagebox.showerror("Error", "No se pudo guardar el nickname")

    def send_message(self):
        try:
            # Obtener IP del combo si está seleccionada, sino del entry
            dest_ip = self.ip_combo.get()
            if dest_ip == "Selecciona IP":
                dest_ip = self.dest_ip.get()
            
            message = self.msg_entry.get()
            if message and dest_ip and self.nickname:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((dest_ip, self.PORT))
                encrypted_message = self.cipher_suite.encrypt(f"{self.nickname}: {message}".encode())
                client.send(encrypted_message)
                client.close()
                self.chat_area.insert(tk.END, f"Tú: {message}\n")
                self.msg_entry.delete(0, tk.END)
                
                # Guardar la IP usada
                self.save_ip(dest_ip)
            elif not self.nickname:
                messagebox.showerror("Error", "Por favor establece un nickname primero")
        except:
            messagebox.showerror("Error", "No se pudo enviar el mensaje")
            
    def check_connection(self, ip):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)
            test_socket.connect((ip, self.PORT))
            
            # Enviar mensaje de prueba
            test_message = self.cipher_suite.encrypt(b"test_connection")
            test_socket.send(test_message)
            test_socket.close()
            return True
        except:
            return False

    def connection_checker(self):
        while True:
            if time.time() - self.last_connection_check >= self.check_interval:
                self.last_connection_check = time.time()
                
                # Verificar IP seleccionada
                ip_to_check = self.ip_combo.get()
                if ip_to_check and ip_to_check != "Selecciona IP":
                    if self.check_connection(ip_to_check):
                        self.window.after(0, self.update_connection_status, True)
                    else:
                        self.window.after(0, self.update_connection_status, False)
            time.sleep(1)

    def update_connection_status(self, is_connected):
        if is_connected:
            self.connection_canvas.itemconfig(self.led, fill='green')
            self.connection_label.config(text="Conectado")
        else:
            self.connection_canvas.itemconfig(self.led, fill='red')
            self.connection_label.config(text="Sin conexión")

    def receive_messages(self):
        while True:
            try:
                client, address = self.socket.accept()
                encrypted_message = client.recv(1024)
                
                # Ignorar mensajes de prueba de conexión
                if encrypted_message == self.cipher_suite.encrypt(b"test_connection"):
                    client.close()
                    continue
                
                # Procesar mensajes normales
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
