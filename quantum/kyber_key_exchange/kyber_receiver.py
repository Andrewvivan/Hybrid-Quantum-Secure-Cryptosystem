import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import hashlib
import threading
from queue import Queue
from kyber_wrapper1024 import generate_keypair, decapsulate
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

class BB84ReceiverGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Kyber Key Exchange - Receiver")
        self.root.geometry("800x600")

        self.public_key = None
        self.private_key = None
        self.shared_secret = None
        self.encapsulated_key = None

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill='both', expand=True)

        self.setup_input_frame(main_frame)

        self.setup_output_frame(main_frame)

        self.queue = Queue()
        self.listening = False
        self.server_socket = None
        self.received_data = None
        self.client_socket = None

    def setup_input_frame(self, parent):
        input_frame = ttk.LabelFrame(parent, text="Configuration", padding="10")
        input_frame.pack(fill='x', padx=5, pady=5)

        key_frame = ttk.LabelFrame(input_frame, text="Kyber Key Processing", padding="10")
        key_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(key_frame, text="Generate Kyber Keys", 
                  command=self.generate_kyber_keys).pack(pady=5)

        public_key_frame = ttk.Frame(key_frame)
        public_key_frame.pack(fill='x', pady=5)

        ttk.Label(public_key_frame, text="Public Key:").pack(side='left')
        self.public_key_text = ttk.Entry(public_key_frame, width=50)

        self.public_key_text.pack(side='left', padx=5)
        ttk.Button(public_key_frame, text="Copy", 
                  command=lambda: self.copy_to_clipboard(self.public_key_text.get())).pack(side='left')

        private_key_frame = ttk.Frame(key_frame)
        private_key_frame.pack(fill='x', pady=5)

        ttk.Label(private_key_frame, text="Private Key (hidden):").pack(side='left')
        self.private_key_text = ttk.Entry(private_key_frame, width=50, show="*")

        self.private_key_text.pack(side='left', padx=5)
        ttk.Button(private_key_frame, text="Copy", 
                  command=lambda: self.copy_to_clipboard(self.private_key_text.get())).pack(side='left')

        encap_key_frame = ttk.Frame(key_frame)
        encap_key_frame.pack(fill='x', pady=5)

        ttk.Label(encap_key_frame, text="Encapsulated Key:").pack(side='left')
        self.encapsulated_key_text = ttk.Entry(encap_key_frame, width=50)

        self.encapsulated_key_text.pack(side='left', padx=5)
        ttk.Button(encap_key_frame, text="Copy", 
                  command=lambda: self.copy_to_clipboard(self.encapsulated_key_text.get())).pack(side='left')
        
        ttk.Button(encap_key_frame, text="Decapsulate", 
                  command=self.manual_decapsulate).pack(side='left', padx=5)

        shared_secret_frame = ttk.Frame(key_frame)
        shared_secret_frame.pack(fill='x', pady=5)
        ttk.Label(shared_secret_frame, text="Shared Secret:").pack(side='left')

        self.shared_secret_text = ttk.Entry(shared_secret_frame, width=50, show="*")
        self.shared_secret_text.pack(side='left', padx=5)
        ttk.Button(shared_secret_frame, text="Copy", 
                  command=lambda: self.copy_to_clipboard(self.shared_secret_text.get())).pack(side='left')

        send_auth_frame = ttk.Frame(input_frame)
        send_auth_frame.pack(fill='x', padx=5, pady=5)

        send_key_frame = ttk.LabelFrame(send_auth_frame, text="Send Public Key", padding="10")
        send_key_frame.pack(side='left', fill='x', expand=True, padx=(0, 5))

        sender_frame = ttk.Frame(send_key_frame)
        sender_frame.pack(fill='x', pady=5)
        
        ttk.Label(sender_frame, text="Sender's IP:").pack(side='left')
        self.sender_ip = ttk.Entry(sender_frame, width=15)
        self.sender_ip.pack(side='left', padx=5)

        ttk.Label(sender_frame, text="Port:").pack(side='left')
        self.sender_port = ttk.Entry(sender_frame, width=10)
        self.sender_port.pack(side='left', padx=5)
        self.sender_port.insert(0, "12345")

        ttk.Button(send_key_frame, text="Send Public Key to Sender", 
                command=self.send_public_key).pack(pady=5)

        self.setup_auth_frame(send_auth_frame)

        vpn_frame = ttk.Frame(input_frame)
        vpn_frame.pack(fill='x', pady=5)
        local_ip = self.get_vpn_ip()

        ttk.Label(vpn_frame, text="Private IP:").pack(side='left', padx=5)
        self.vpn_label = ttk.Label(vpn_frame, text=local_ip if local_ip else "Not Connected")
        self.vpn_label.pack(side='left', padx=5)

        listen_frame = ttk.Frame(input_frame)
        listen_frame.pack(fill='x', pady=5)
        
        ttk.Label(listen_frame, text="Listen on:").pack(side='left', padx=5)
        self.host_entry = ttk.Entry(listen_frame, width=15)
        self.host_entry.pack(side='left', padx=5)
        self.host_entry.insert(0, "0.0.0.0")
        
        ttk.Label(listen_frame, text="Port:").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(listen_frame, width=10)
        self.port_entry.pack(side='left', padx=5)
        self.port_entry.insert(0, "12345")

        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill='x', pady=5)
        
        self.listen_button = ttk.Button(button_frame, text="Start Listening",
                                      command=self.start_listening)
        self.listen_button.pack(side='left', padx=5)
        
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

        psk_hash = hashlib.sha256(psk.encode()).hexdigest()
        self.stored_psk_hash = psk_hash

        self.auth_status_label.config(text="Waiting for Authentication", foreground="orange")
        self.auth_button.config(state='disabled')
        self.psk_entry.config(state='disabled')
        self.output.insert(tk.END, "\nWaiting for sender authentication...\n")

    def handle_auth_request(self, received_data, addr):
        if hasattr(self, 'stored_psk_hash'):
            if received_data['psk_hash'] == self.stored_psk_hash:
                psk = self.psk_entry.get().strip()
                aes_key = derive_aes_key(psk)
                encrypted_sender_ip = received_data.get('sender_ip', {})

                try:
                    sender_ip = decrypt_data(encrypted_sender_ip, aes_key)  
                    encrypted_receiver_ip = encrypt_data(self.get_vpn_ip(), aes_key)  

                    response = {
                        'status': 'authenticated',
                        'receiver_ip': encrypted_receiver_ip
                    }
                    self.client_socket.sendall(json.dumps(response).encode())
                    self.root.after(0, lambda: self.update_auth_status(True, sender_ip))
                except Exception as e:
                    response = {'status': 'failed', 'error': str(e)}
                    self.client_socket.sendall(json.dumps(response).encode())
                    self.root.after(0, lambda: self.update_auth_status(False))
            else:
                response = {'status': 'failed'}
                self.client_socket.sendall(json.dumps(response).encode())
                self.root.after(0, lambda: self.update_auth_status(False))
        else:
            response = {'status': 'not_ready'}
            self.client_socket.sendall(json.dumps(response).encode())
            self.root.after(0, lambda: self.output.insert(tk.END, "No PSK set on receiver\n"))

    def update_auth_status(self, success, sender_ip=None):
        """Update authentication status in GUI thread"""
        if success:
            self.is_authenticated = True
            status_text = f"Authenticated with Sender at {sender_ip}"
            self.auth_status_label.config(text=status_text, foreground="green")
            self.auth_button.config(state='disabled')
            self.psk_entry.config(state='disabled')
            self.output.insert(tk.END, f"\nAuthentication successful with sender at {sender_ip}\n")
        else:
            self.is_authenticated = False
            self.auth_status_label.config(text="Authentication Failed", foreground="red")
            self.auth_button.config(state='normal')
            self.psk_entry.config(state='normal')
            self.output.insert(tk.END, "\nAuthentication failed\n")

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.output.insert(tk.END, "Copied to clipboard!\n")

    def send_public_key(self):
        if not self.public_key:
            messagebox.showerror("Error", "Please generate Kyber keys first")
            return
            
        try:
            host = self.sender_ip.get()
            port = int(self.sender_port.get())
            
            if not host:
                messagebox.showerror("Error", "Please enter sender's IP")
                return

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))

                data = {
                    'public_key': self.public_key.hex()
                }

                s.sendall(json.dumps(data).encode())

                response = json.loads(s.recv(1024).decode())
                
                if response.get('status') == 'success':
                    self.output.insert(tk.END, "Successfully sent public key to sender\n")
                else:
                    self.output.insert(tk.END, "Error: Sender reported failure in processing key\n")
                    
        except Exception as e:
            self.display_error(f"Error sending public key: {e}")

    def generate_kyber_keys(self):
        try:
            self.public_key, self.private_key = generate_keypair()
            self.public_key_text.delete(0, tk.END)
            self.public_key_text.insert(0, self.public_key.hex())
            self.private_key_text.delete(0, tk.END)
            self.private_key_text.insert(0, self.private_key.hex())
            self.output.insert(tk.END, "Kyber keys generated successfully!\n")
        except Exception as e:
            self.display_error(f"Error generating Kyber keys: {e}")

    def manual_decapsulate(self):
        try:
            if not self.private_key:
                messagebox.showerror("Error", "Please generate Kyber keys first")
                return
                
            encapsulated_key = self.encapsulated_key_text.get().strip()
            if not encapsulated_key:
                messagebox.showerror("Error", "No encapsulated key available")
                return

            encapsulated_key_bytes = bytes.fromhex(encapsulated_key)
            self.shared_secret = decapsulate(encapsulated_key_bytes, self.private_key)
            
            self.shared_secret_text.delete(0, tk.END)
            self.shared_secret_text.insert(0, self.shared_secret.hex())
            self.output.insert(tk.END, "Successfully decapsulated shared secret\n")
        except Exception as e:
            self.display_error(f"Error decapsulating key: {e}")

    def handle_encapsulated_key(self, encapsulated_key):
        try:
            if not self.is_authenticated:
                self.output.insert(tk.END, "Error: Sender not authenticated. Cannot accept encapsulated key.\n")
                return False
            self.encapsulated_key_text.delete(0, tk.END)
            self.encapsulated_key_text.insert(0, encapsulated_key)
            self.output.insert(tk.END, "Received encapsulated key. Press 'Decapsulate' to generate shared secret.\n")
            return True
        except Exception as e:
            self.display_error(f"Error handling encapsulated key: {e}")
            return False

    def listen_for_connection(self):
        try:
            while self.listening:
                self.client_socket, addr = self.server_socket.accept()
                self.output.insert(tk.END, f"\nConnected to {addr}\n")

                data = self.client_socket.recv(16384).decode()
                received_data = json.loads(data)

                if 'request' in received_data and received_data['request'] == 'authenticate':
                    self.handle_auth_request(received_data, addr)
                elif 'encapsulated_key' in received_data:
                    success = self.handle_encapsulated_key(received_data['encapsulated_key'])
                    response = {'status': 'success' if success else 'error'}
                    self.client_socket.sendall(json.dumps(response).encode())
                elif 'public_key' in received_data:
                    self.handle_public_key(received_data['public_key'])

                self.client_socket.close()

        except Exception as e:
            if self.listening:
                self.display_error(f"Error in connection: {e}")

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

    def start_listening(self):
        if not self.listening:
            try:
                if not self.private_key:
                    messagebox.showerror("Error", "Please generate Kyber keys first")
                    return
                    
                host = self.host_entry.get()
                port = int(self.port_entry.get())
                
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
                self.output.insert(tk.END, "Waiting for incoming connections...\n")
                
                threading.Thread(target=self.listen_for_connection, daemon=True).start()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            self.stop_listening()

    def stop_listening(self):
        if self.server_socket:
            self.server_socket.close()
        self.listening = False
        self.listen_button.config(text="Start Listening")
        self.output.insert(tk.END, "Stopped listening.\n")

    def display_error(self, error_message):
        self.output.insert(tk.END, f"\nError: {error_message}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = BB84ReceiverGUI(root)
    root.mainloop()
