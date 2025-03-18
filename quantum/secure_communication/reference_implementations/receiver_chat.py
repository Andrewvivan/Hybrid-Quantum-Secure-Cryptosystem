import socket
import base64
import os
import threading
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib

class QuantumSecureReceiver:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Quantum Secure Communication - Receiver")
        self.window.geometry("600x800")
        
        self.setup_configuration_frame()
        self.setup_chat_frame()

        self.server_socket = None
        self.client_socket = None
        self.symmetric_key = None
        self.quantum_key = None
        self.quantum_key_hash = None
        self.kyber_key = None
        self.hybrid_key = None
        self.show_encrypted = False
        self.key_mismatch_prompted = False
        
        # Buffer to accumulate incoming data for proper message assembly.
        self.recv_buffer = ""

    def setup_configuration_frame(self):
        config_frame = ttk.LabelFrame(self.window, text="Configuration", padding="10")
        config_frame.pack(fill='x', padx=5, pady=5)

        # Local IP
        ip_frame = ttk.Frame(config_frame)
        ip_frame.pack(fill='x', pady=5)
        ttk.Label(ip_frame, text="Private IP:").pack(side='left', padx=5)
        self.local_ip_label = ttk.Label(ip_frame, text=self.get_local_ip())
        self.local_ip_label.pack(side='left', padx=5)

        # Key Selection Frame - Modified to separate radio buttons and key entry
        key_frame = ttk.Frame(config_frame)
        key_frame.pack(fill='x', pady=5)

        # Radio buttons frame
        radio_frame = ttk.Frame(key_frame)
        radio_frame.pack(fill='x', pady=5)

        self.key_choice_var = tk.StringVar()
        self.key_choice_var.set("quantum")

        ttk.Radiobutton(radio_frame, text="Quantum Key", variable=self.key_choice_var, 
                        value="quantum", command=self.toggle_key_entry).pack(side='left', padx=5)
        ttk.Radiobutton(radio_frame, text="Kyber Key", variable=self.key_choice_var,
                        value="kyber", command=self.toggle_key_entry).pack(side='left', padx=5)
        ttk.Radiobutton(radio_frame, text="Hybrid Key", variable=self.key_choice_var,
                        value="hybrid", command=self.toggle_key_entry).pack(side='left', padx=5)

        # Key entry frame
        key_entry_frame = ttk.Frame(key_frame)
        key_entry_frame.pack(fill='x', pady=5)

        self.key_label = ttk.Label(key_entry_frame, text="Choose Your Key:")
        self.key_label.pack(side='left', padx=5)
        self.key_entry = ttk.Entry(key_entry_frame, width=50)
        self.key_entry.pack(side='left', padx=5)
        self.copy_button = ttk.Button(key_entry_frame, text="Copy", command=self.copy_key)
        self.copy_button.pack(side='left', padx=5)
        self.delete_button = ttk.Button(key_entry_frame, text="Delete", command=self.delete_key)
        self.delete_button.pack(side='left', padx=5)

        # Connection Settings
        conn_frame = ttk.Frame(config_frame)
        conn_frame.pack(fill='x', pady=5)
        ttk.Label(conn_frame, text="Port:").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.pack(side='left', padx=5)
        self.port_entry.insert(0, "5000")

        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill='x', pady=5)
        self.start_server_button = ttk.Button(button_frame, text="Start Listening", command=self.start_server)
        self.start_server_button.pack(side='left', padx=5)
        ttk.Button(button_frame, text="Refresh IP Status", command=self.refresh_vpn_status).pack(side='left', padx=5)
        self.end_chat_button = ttk.Button(button_frame, text="End Chat", command=self.end_chat, state='disabled')
        self.end_chat_button.pack(side='left', padx=5)

    def copy_key(self):
        key = self.key_entry.get()
        if key:
            self.window.clipboard_clear()
            self.window.clipboard_append(key)

    def delete_key(self):
        self.key_entry.delete(0, tk.END)

    def toggle_key_entry(self):
        key_type = self.key_choice_var.get()
        if key_type == "quantum":
            self.key_label.config(text="Quantum Key:")
            self.key_entry.config(show="*")
        elif key_type == "hybrid":
            self.key_label.config(text="Hybrid Key:")
            self.key_entry.config(show="")
        else:
            self.key_label.config(text="Kyber Key:")
            self.key_entry.config(show="")

    def generate_key_from_kyber_key(self, kyber_key):
        return hashlib.sha256(kyber_key.encode()).digest()
    
    def generate_key_from_hybrid_key(self, hybrid_key):
        try:
            if len(hybrid_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in hybrid_key):
                return bytes.fromhex(hybrid_key)
            else:
                return hashlib.sha256(hybrid_key.encode()).digest()
        except Exception:
            return hashlib.sha256(hybrid_key.encode()).digest()

    def start_server(self):
        key = self.key_entry.get()
        port = int(self.port_entry.get())
        
        if not key:
            messagebox.showerror("Error", "Please enter Key")
            return
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(1)
            
            self.chat_text.insert(tk.END, f"Waiting for sender connection on port {port}...\n")
            self.chat_text.update_idletasks()
            
            self.client_socket, client_address = self.server_socket.accept()
            self.chat_text.insert(tk.END, f"Connected to sender from {client_address}\n")
            
            if self.key_choice_var.get() == "quantum":
                self.quantum_key = key
                self.quantum_key_hash = hashlib.sha256(key.encode()).hexdigest()
                self.symmetric_key = self.generate_key_from_quantum_key(key)
            elif self.key_choice_var.get() == "hybrid":
                self.hybrid_key = key
                self.symmetric_key = self.generate_key_from_hybrid_key(key)
            else:
                self.kyber_key = key
                self.symmetric_key = self.generate_key_from_kyber_key(key)

            received_key = self.client_socket.recv(2048).decode('utf-8')
            expected_key = (self.quantum_key_hash if self.key_choice_var.get() == "quantum"
                            else (self.hybrid_key if self.key_choice_var.get() == "hybrid" 
                                  else self.kyber_key))
            
            if received_key != expected_key:
                response = messagebox.askyesno("Key Mismatch", "Key might be incorrect. Do you want to continue?")
                if not response:
                    self.client_socket.close()
                    return
            
            self.send_button.config(state='normal')
            self.send_file_button.config(state='normal')
            self.end_chat_button.config(state='normal')
            self.start_server_button.config(state='disabled')
            
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
        except Exception as e:
            messagebox.showerror("Server Error", str(e))

    def setup_chat_frame(self):
        chat_frame = ttk.Frame(self.window)
        chat_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.chat_text = scrolledtext.ScrolledText(chat_frame, height=20, width=60, wrap=tk.WORD)
        self.chat_text.pack(pady=10, fill='both', expand=True)

        message_frame = ttk.Frame(chat_frame)
        message_frame.pack(fill='x', pady=5)

        self.message_entry = ttk.Entry(message_frame, width=50, font=("Helvetica", 14))
        self.message_entry.pack(side='left', padx=5, expand=True, fill='x')
        self.message_entry.bind('<Return>', self.send_message)

        button_frame = ttk.Frame(chat_frame)
        button_frame.pack(fill='x', pady=5)
        self.send_button = ttk.Button(button_frame, text="Send", command=self.send_message, state='disabled')
        self.send_button.pack(side='left', padx=5)
        self.send_file_button = ttk.Button(button_frame, text="Send File", command=self.send_file, state='disabled')
        self.send_file_button.pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear Chat", command=self.clear_chat).pack(side='left', padx=5)

    def send_file(self):
        if not self.client_socket:
            messagebox.showerror("Error", "Not connected")
            return

        file_path = filedialog.askopenfilename(title="Select file to send")
        if not file_path:
            return

        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
            file_size = os.path.getsize(file_path)
            
            b64_content = base64.b64encode(file_content).decode('utf-8')
            encrypted_file = self.encrypt_message(b64_content, self.symmetric_key)
            encrypted_file_bytes = encrypted_file.encode('utf-8')
            data_length = len(encrypted_file_bytes)
            file_name = os.path.basename(file_path)
            # Build header in the format: FILE:filename:length\n
            header = f"FILE:{file_name}:{data_length}\n"
            
            self.client_socket.sendall(header.encode('utf-8'))
            self.client_socket.sendall(encrypted_file_bytes)
            
            self.chat_text.insert(tk.END, f"You sent a file: {file_name} ({file_size/1024:.2f}KB)\n")
        except Exception as e:
            messagebox.showerror("File Send Error", str(e))

    def get_local_ip(self):
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except Exception:
            return "Unable to retrieve IP"

    def refresh_vpn_status(self):
        new_ip = self.get_local_ip()
        self.local_ip_label.config(text=new_ip)
        messagebox.showinfo("IP Status", f"Local IP refreshed: {new_ip}")

    def clear_chat(self):
        self.chat_text.delete(1.0, tk.END)

    def end_chat(self):
        try:
            response = messagebox.askyesno("End Chat", "Do you want to disconnect?")
            if response:
                self.client_socket.send("DISCONNECT".encode('utf-8'))
                self.client_socket.close()
                if self.server_socket:
                    self.server_socket.close()
                self.send_button.config(state='disabled')
                self.send_file_button.config(state='disabled')
                self.end_chat_button.config(state='disabled')
                self.start_server_button.config(state='normal')
                self.chat_text.insert(tk.END, "You have disconnected from the chat.\n")
        except Exception as e:
            messagebox.showerror("Disconnect Error", str(e))

    def generate_key_from_quantum_key(self, quantum_key):
        salt = b'quantum_secure_salt'
        key = PBKDF2(quantum_key.encode('utf-8'), salt, dkLen=32)
        return key

    def encrypt_message(self, message, key):
        if isinstance(message, bytes):
            message_bytes = message
        else:
            message_bytes = message.encode('utf-8')
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message_bytes)
        return base64.b64encode(nonce + ciphertext + tag).decode('utf-8')

    def decrypt_message(self, ciphertext, key):
        raw = base64.b64decode(ciphertext)
        nonce = raw[:16]
        ciphertext = raw[16:-16]
        tag = raw[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        try:
            return decrypted.decode('utf-8')
        except UnicodeDecodeError:
            return decrypted

    def send_message(self, event=None):
        message = self.message_entry.get()
        if not message:
            return
        try:
            encrypted_message = self.encrypt_message(message, self.symmetric_key)
            self.client_socket.send(encrypted_message.encode('utf-8'))
            self.chat_text.insert(tk.END, f"You: {message}\n")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(16384)
                if not data:
                    break
                self.recv_buffer += data.decode('utf-8')

                if self.recv_buffer.startswith("FILE:"):
                    newline_index = self.recv_buffer.find("\n")
                    if newline_index == -1:
                        continue  
                    header = self.recv_buffer[:newline_index]
                    parts = header.split(":")
                    if len(parts) != 3:
                        self.chat_text.insert(tk.END, "Invalid file header received.\n")
                        self.recv_buffer = ""
                        continue
                    _, file_name, data_length_str = parts
                    try:
                        data_length = int(data_length_str)
                    except ValueError:
                        self.chat_text.insert(tk.END, "Invalid file length received.\n")
                        self.recv_buffer = ""
                        continue
                    total_length = newline_index + 1 + data_length
                    if len(self.recv_buffer) < total_length:
                        continue 
                    encrypted_file = self.recv_buffer[newline_index+1:total_length]
                    self.recv_buffer = self.recv_buffer[total_length:]
                    try:
                        decrypted_file_content = self.decrypt_message(encrypted_file, self.symmetric_key)
                        file_content = base64.b64decode(decrypted_file_content)
                        is_decrypted = True
                    except Exception as e:
                        save_raw_response = messagebox.askyesno(
                            "Decryption Failed",
                            f"Failed to decrypt file '{file_name}': {str(e)}. Do you want to save the encrypted version instead?"
                        )
                        if save_raw_response:
                            file_content = base64.b64decode(encrypted_file)
                            is_decrypted = False
                            if not file_name.endswith('.encrypted'):
                                file_name += '.encrypted'
                        else:
                            self.chat_text.insert(tk.END, f"File '{file_name}' decryption failed, and saving was skipped.\n")
                            continue
                    save_path = filedialog.asksaveasfilename(
                        defaultextension="",
                        initialfile=file_name,
                        title="Save received file as"
                    )
                    if save_path:
                        with open(save_path, 'wb') as file:
                            file.write(file_content)
                        status = "decrypted" if is_decrypted else "encrypted"
                        self.chat_text.insert(tk.END, f"File saved as: {save_path} ({status})\n")
                    continue
                else:
                    # Process as a normal text message.
                    if self.recv_buffer:
                        try:
                            decrypted_message = self.decrypt_message(self.recv_buffer, self.symmetric_key)
                            if isinstance(decrypted_message, bytes):
                                self.chat_text.insert(tk.END, "Received binary data that cannot be displayed as text.\n")
                            else:
                                self.chat_text.insert(tk.END, f"Sender: {decrypted_message}\n")
                        except Exception:
                            if not self.key_mismatch_prompted:
                                self.key_mismatch_prompted = True
                                quantum_key_response = messagebox.askyesno(
                                    "Key Mismatch", 
                                    "Key might be incorrect. Do you want to display text anyways?"
                                )
                                if quantum_key_response:
                                    self.show_encrypted = True
                            if self.show_encrypted:
                                self.chat_text.insert(tk.END, f"[Encrypted]: {self.recv_buffer}\n")
                            else:
                                self.chat_text.insert(tk.END, "Message rejected due to key mismatch.\n")
                        self.recv_buffer = ""
            except Exception as e:
                messagebox.showerror("Receive Error", str(e))
                break

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    receiver = QuantumSecureReceiver()
    receiver.run()
