import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import random
import hashlib
import threading
from queue import Queue
from kyber_wrapper1024 import generate_keypair, encapsulate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def derive_aes_key(psk):
    return hashlib.sha256(psk.encode()).digest()

def encrypt_data(data, key):
    if isinstance(data, str):
        data = data.encode()

    iv = os.urandom(16)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return {
        'iv': iv.hex(),
        'data': encrypted_data.hex()
    }

def decrypt_data(encrypted_dict, key):
    iv = bytes.fromhex(encrypted_dict['iv'])
    encrypted_data = bytes.fromhex(encrypted_dict['data'])

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode()

class BB84SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Kyber Key Exchange - Sender")
        self.root.geometry("800x600")

        self.receiver_public_key = None
        self.encapsulated_key = None
        self.shared_secret = None

        self.listening = False
        self.server_socket = None

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill='both', expand=True)

        self.setup_input_frame(main_frame)

        self.setup_output_frame(main_frame)

        self.queue = Queue()

    def setup_input_frame(self, parent):
        input_frame = ttk.LabelFrame(parent, text="Configuration", padding="10")
        input_frame.pack(fill='x', padx=5, pady=5)

        key_frame = ttk.LabelFrame(input_frame, text="Kyber Key Processing", padding="10")
        key_frame.pack(fill='x', padx=5, pady=5)

        public_key_frame = ttk.Frame(key_frame)
        public_key_frame.pack(fill='x', pady=5)
        ttk.Label(public_key_frame, text="Receiver's Public Key:").pack(side='left')
        self.public_key_entry = ttk.Entry(public_key_frame, width=50)
        self.public_key_entry.pack(side='left', padx=5)

        ttk.Button(key_frame, text="Process Public Key", 
                command=self.process_public_key).pack(pady=5)

        encap_frame = ttk.Frame(key_frame)
        encap_frame.pack(fill='x', pady=5)
        ttk.Label(encap_frame, text="Encapsulated Key:").pack(side='left')
        self.encapsulated_key_text = ttk.Entry(encap_frame, width=50)
        self.encapsulated_key_text.pack(side='left', padx=5)

        ttk.Button(encap_frame, text="Copy", 
                command=lambda: self.copy_to_clipboard(self.encapsulated_key_text.get())).pack(side='left')

        secret_frame = ttk.Frame(key_frame)
        secret_frame.pack(fill='x', pady=5)
        ttk.Label(secret_frame, text="Shared Secret:").pack(side='left')
        self.shared_secret_text = ttk.Entry(secret_frame, width=50, show="*")
        self.shared_secret_text.pack(side='left', padx=5)

        ttk.Button(secret_frame, text="Copy", 
                command=lambda: self.copy_to_clipboard(self.shared_secret_text.get())).pack(side='left')

        listen_auth_frame = ttk.Frame(input_frame)
        listen_auth_frame.pack(fill='x', padx=5, pady=5)

        listen_frame = ttk.LabelFrame(listen_auth_frame, text="Listen for Public Key", padding="10")
        listen_frame.pack(side='left', fill='x', expand=True, padx=(0, 5))

        listen_config_frame = ttk.Frame(listen_frame)
        listen_config_frame.pack(fill='x', pady=5)
        ttk.Label(listen_config_frame, text="Listen on:").pack(side='left', padx=5)
        self.listen_host_entry = ttk.Entry(listen_config_frame, width=15)
        self.listen_host_entry.pack(side='left', padx=5)
        self.listen_host_entry.insert(0, "0.0.0.0")

        ttk.Label(listen_config_frame, text="Port:").pack(side='left', padx=5)
        self.listen_port_entry = ttk.Entry(listen_config_frame, width=10)
        self.listen_port_entry.pack(side='left', padx=5)
        self.listen_port_entry.insert(0, "12345")

        self.listen_button = ttk.Button(listen_frame, text="Start Listening",
                                        command=self.toggle_listening)
        self.listen_button.pack(pady=5)

        self.setup_auth_frame(listen_auth_frame)

        vpn_frame = ttk.Frame(input_frame)
        vpn_frame.pack(fill='x', pady=5)
        local_ip = self.get_vpn_ip()
        ttk.Label(vpn_frame, text="Private IP:").pack(side='left', padx=5)
        self.vpn_label = ttk.Label(vpn_frame, text=local_ip if local_ip else "Not Connected")
        self.vpn_label.pack(side='left', padx=5)

        conn_frame = ttk.Frame(input_frame)
        conn_frame.pack(fill='x', pady=5)
        ttk.Label(conn_frame, text="Receiver IP:").pack(side='left', padx=5)

        self.host_entry = ttk.Entry(conn_frame, width=15)
        self.host_entry.pack(side='left', padx=5)

        ttk.Label(conn_frame, text="Port:").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.pack(side='left', padx=5)
        self.port_entry.insert(0, "12345")

        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill='x', pady=5)
        ttk.Button(button_frame, text="Send Encapsulated Key", 
                command=self.send_encapsulated_key).pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Clear Output",
                command=self.clear_output).pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Refresh IP Status",
                command=self.refresh_vpn_status).pack(side='left', padx=5)
        
    def setup_auth_frame(self, parent):
        auth_frame = ttk.LabelFrame(parent, text="Authentication", padding="10")
        auth_frame.pack(side='right', fill='x', expand=True, padx=(5, 0))

        psk_frame = ttk.Frame(auth_frame)
        psk_frame.pack(fill='x', pady=5)
        
        ttk.Label(psk_frame, text="Pre-shared Key:").pack(side='left', padx=5)
        self.psk_entry = ttk.Entry(psk_frame, show="*", width=30)
        self.psk_entry.pack(side='left', padx=5)

        self.auth_button = ttk.Button(psk_frame, text="Check Authentication", 
                                    command=self.authenticate)
        self.auth_button.pack(side='left', padx=5)

        self.auth_status_label = ttk.Label(psk_frame, text="Not Authenticated", foreground="red")
        self.auth_status_label.pack(side='left', padx=5)

        self.is_authenticated = False

    def authenticate(self):
        psk = self.psk_entry.get().strip()
        if not psk:
            messagebox.showerror("Error", "Pre-shared key cannot be empty")
            return
        
        aes_key = derive_aes_key(psk)
        encrypted_sender_ip = encrypt_data(self.get_vpn_ip(), aes_key) 
        
        try:
            receiver_ip = self.host_entry.get().strip()
            if not receiver_ip:
                messagebox.showerror("Error", "Receiver IP is required")
                return
                
            port = int(self.port_entry.get())
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((receiver_ip, port))
                auth_data = {
                    'request': 'authenticate',
                    'psk_hash': hashlib.sha256(psk.encode()).hexdigest(),
                    'sender_ip': encrypted_sender_ip  
                }
                s.sendall(json.dumps(auth_data).encode())

                response = s.recv(4096).decode()
                response_data = json.loads(response)

                if response_data.get('status') == 'authenticated':
                    encrypted_receiver_ip = response_data.get('receiver_ip', '')
                    decrypted_receiver_ip = decrypt_data(encrypted_receiver_ip, aes_key) 
                    self.auth_success(decrypted_receiver_ip)
                elif response_data.get('status') == 'not_ready':
                    self.auth_status_label.config(text="Receiver not ready", foreground="orange")
                    messagebox.showinfo("Authentication", "Receiver is not ready. Please wait for receiver to enter PSK.")
                else:
                    self.auth_failure()
                    
        except Exception as e:
            self.display_error(f"Authentication error: {e}")
            self.auth_failure()

    def auth_success(self, receiver_ip):
        self.is_authenticated = True
        status_text = f"Authenticated with Receiver at: {receiver_ip}"
        self.auth_status_label.config(text=status_text, foreground="green")
        self.auth_button.config(state='disabled')
        self.psk_entry.config(state='disabled')
        self.output.insert(tk.END, f"\nAuthentication successful with Receiver at {receiver_ip}\n")

    def auth_failure(self):
        self.is_authenticated = False
        self.auth_status_label.config(text="Authentication Failed", foreground="red")
        self.auth_button.config(state='normal')
        self.psk_entry.config(state='normal')
        
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.output.insert(tk.END, "Copied to clipboard!\n")

    def toggle_listening(self):
        if not self.listening:
            self.start_listening()
        else:
            self.stop_listening()

    def listen_for_connection(self):
        try:
            while self.listening:
                client_socket, addr = self.server_socket.accept()
                self.output.insert(tk.END, f"\nConnected to {addr}\n")
                
                data = client_socket.recv(16384).decode()
                received_data = json.loads(data)
                
                if 'public_key' in received_data:
                    self.public_key_entry.delete(0, tk.END)
                    self.public_key_entry.insert(0, received_data['public_key'])
                    self.output.insert(tk.END, "Received public key from receiver\n")
                    response = {'status': 'success'}
                else:
                    response = {'status': 'error'}
                
                client_socket.sendall(json.dumps(response).encode())
                client_socket.close()
                
        except Exception as e:
            if self.listening:
                self.display_error(f"Error in connection: {e}")

    def start_listening(self):
        try:
            host = self.listen_host_entry.get()
            port = int(self.listen_port_entry.get())
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen()
            
            self.listening = True
            self.listen_button.config(text="Stop Listening")
            
            vpn_ip = self.get_vpn_ip()
            if vpn_ip:
                self.output.insert(tk.END, f"VPN IP: {vpn_ip}\n")
            self.output.insert(tk.END, f"Listening on port: {port}\n")
            self.output.insert(tk.END, "Waiting for public key from receiver...\n")
            
            threading.Thread(target=self.listen_for_connection, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def stop_listening(self):
        if self.server_socket:
            self.server_socket.close()
        self.listening = False
        self.listen_button.config(text="Start Listening")
        self.output.insert(tk.END, "Stopped listening.\n")


    def process_public_key(self):
        try:
            public_key_hex = self.public_key_entry.get().strip()
            if not public_key_hex:
                messagebox.showerror("Error", "Please enter receiver's public key")
                return

            self.receiver_public_key = bytes.fromhex(public_key_hex)

            self.encapsulated_key, self.shared_secret = encapsulate(self.receiver_public_key)

            self.encapsulated_key_text.delete(0, tk.END)
            self.encapsulated_key_text.insert(0, self.encapsulated_key.hex())
            
            self.shared_secret_text.delete(0, tk.END)
            self.shared_secret_text.insert(0, self.shared_secret.hex())
            
            self.output.insert(tk.END, "Successfully processed public key and generated shared secret\n")
        except Exception as e:
            self.display_error(f"Error processing public key: {e}")

    def send_encapsulated_key(self):
        if not self.encapsulated_key:
            messagebox.showerror("Error", "Please process receiver's public key first")
            return
        
        if not self.is_authenticated:
            messagebox.showerror("Error", "Please authenticate with receiver first")
            return
            
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            if not host:
                messagebox.showerror("Error", "Please enter receiver's VPN IP")
                return

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))

                data = {
                    'encapsulated_key': self.encapsulated_key.hex()
                }

                s.sendall(json.dumps(data).encode())

                response = json.loads(s.recv(1024).decode())
                
                if response.get('status') == 'success':
                    self.output.insert(tk.END, "Successfully sent encapsulated key to receiver\n")
                else:
                    self.output.insert(tk.END, "Error: Receiver reported failure in processing key\n")
                    
        except Exception as e:
            self.display_error(f"Error sending encapsulated key: {e}")

    def get_vpn_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            self.display_error(f"Error getting IP address: {e}")
            return None

    def get_vpn_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            self.display_error(f"Error getting IP address: {e}")
            return None

    def setup_output_frame(self, parent):
        output_frame = ttk.LabelFrame(parent, text="Results", padding="10")
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.output = scrolledtext.ScrolledText(output_frame, height=20)
        self.output.pack(fill='both', expand=True)

    def clear_output(self):
        self.output.delete(1.0, tk.END)

    def refresh_vpn_status(self):
        local_ip = self.get_vpn_ip()
        self.vpn_label.config(text=local_ip if local_ip else "Not Connected")

    def display_error(self, error_message):
        self.output.insert(tk.END, f"\nError: {error_message}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = BB84SenderGUI(root)
    root.mainloop()
