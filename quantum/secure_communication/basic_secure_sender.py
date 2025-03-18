### ------------------------------------------ Basic Secure Sender ---------------------------------------- ###
# Improved Toggle key entry and GUI ✅
# Kyber Ephemeral key exchange (with forward secrecy) ❌
# HMAC Timestamp Authentication ❌
# Replay Attack Awareness ❌
# Saves Performance Logs ✅
### ------------------------------------------------------------------------------------------------------- ###
import socket
import base64
import os
import threading
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import time
from datetime import datetime
import csv
import os.path

class QuantumSecureSender:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Quantum Secure Communication - Sender")
        width, height = 650, 750
        self.window.geometry(f"{width}x{height}")
        self.center_window(width, height)

        self.setup_configuration_frame()
        self.setup_chat_frame()

        self.socket = None
        self.symmetric_key = None
        self.quantum_key = None
        self.quantum_key_hash = None
        self.kyber_key = None
        self.hybrid_key = None
        self.show_encrypted = False
        self.key_mismatch_prompted = False

        self.recv_buffer = ""
        self.performance_logs = []
        self.message_send_times = {}

    def center_window(self, width, height):
        self.window.update_idletasks() 
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2) - 30 
        y = max(y, 0)
        self.window.geometry(f"{width}x{height}+{x}+{y}")

    def insert_message(self, message):
        timestamp = datetime.now().strftime("%I:%M:%S %p")
        self.chat_text.insert(tk.END, f"[{timestamp}] {message}")

    def log_performance(self, operation, data_size=0, duration=0, additional_info="", category="other", **extra_fields):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "operation": operation,
            "data_size_bytes": data_size,
            "duration_ms": duration,
            "key_type": self.key_choice_var.get(),
            "additional_info": additional_info,
            "category": category
        }
        log_entry.update(extra_fields)
        self.performance_logs.append(log_entry)

    def monitor_network_health(self, interval=10):
        def run_monitoring():
            while self.socket:
                try:
                    start_time = time.perf_counter()
                    ping_message = f"PING:{start_time}"
                    self.socket.send(self.encrypt_message(ping_message, self.symmetric_key).encode('utf-8'))
                    time.sleep(interval)
                except:
                    break
        monitor_thread = threading.Thread(target=run_monitoring)
        monitor_thread.daemon = True
        monitor_thread.start()

    def save_performance_logs(self):
        if not self.performance_logs:
            messagebox.showinfo("Performance Logs", "No performance data to save")
            return

        file_logs = [log for log in self.performance_logs if log.get("category") == "file"]
        message_logs = [log for log in self.performance_logs if log.get("category") == "message"]

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="sender_file_performance_logs.csv",
            title="Save File Performance Logs"
        )
        if file_path:
            fieldnames = ["timestamp", "operation", "data_size_bytes", "duration_ms", "key_type", "additional_info", "category", "file_type", "encryption_type", "decryption_type"]
            file_exists = os.path.isfile(file_path)
            with open(file_path, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                if not file_exists:
                    writer.writeheader()
                for log in file_logs:
                    filtered_log = {key: log.get(key, "") for key in fieldnames}
                    writer.writerow(filtered_log)

        msg_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="sender_message_performance_logs.csv",
            title="Save Message Performance Logs"
        )
        if msg_path:
            fieldnames = ["timestamp", "operation", "data_size_bytes", "duration_ms", "key_type", "additional_info", "category", "message_char_count"]
            file_exists = os.path.isfile(msg_path)
            with open(msg_path, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                if not file_exists:
                    writer.writeheader()
                for log in message_logs:
                    filtered_log = {key: log.get(key, "") for key in fieldnames}
                    writer.writerow(filtered_log)

        messagebox.showinfo("Performance Logs", "Logs saved successfully")
        self.performance_logs = []

    def send_file(self):
        if not self.socket:
            messagebox.showerror("Error", "Not connected")
            return

        file_path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            file_size = os.path.getsize(file_path)
            max_size = 10 * 1024 * 1024 
            if file_size > max_size:
                confirm = messagebox.askyesno(
                    "Large File Warning",
                    f"The selected file is {file_size/1024/1024:.2f}MB. Sending large files may take time. Continue?"
                )
                if not confirm:
                    return

            start_time = time.perf_counter()
            with open(file_path, 'rb') as file:
                file_content = file.read()

            b64_content = base64.b64encode(file_content).decode('utf-8')
            encrypted_file = self.encrypt_message(b64_content, self.symmetric_key, category="file")
            encrypted_file_bytes = encrypted_file.encode('utf-8')
            data_length = len(encrypted_file_bytes)
            file_name = os.path.basename(file_path)
            header = f"FILE:{file_name}:{data_length}\n"
            self.socket.sendall(header.encode('utf-8'))
            self.socket.sendall(encrypted_file_bytes)
            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000
            transfer_rate_kbps = (file_size * 8 / 1024) / (duration_ms / 1000) if duration_ms > 0 else 0
            file_ext = os.path.splitext(file_name)[1] or "unknown"
            self.log_performance("file_transfer", file_size, duration_ms,
                                 additional_info=f"File: {file_name}, Rate: {transfer_rate_kbps:.2f} kbps",
                                 category="file",
                                 file_type=file_ext,
                                 encryption_type="AES-GCM")
            self.insert_message(f"You sent a file: {file_name} ({file_size/1024:.2f}KB) in {duration_ms:.2f}ms\n")
        except Exception as e:
            messagebox.showerror("File Send Error", str(e))

    def setup_configuration_frame(self):
        config_frame = ttk.LabelFrame(self.window, text="Configuration", padding="10")
        config_frame.pack(fill='x', padx=5, pady=5)

        ip_frame = ttk.Frame(config_frame)
        ip_frame.pack(fill='x', pady=5)
        ttk.Label(ip_frame, text="Private IP:").pack(side='left', padx=5)
        self.local_ip_label = ttk.Label(ip_frame, text=self.get_local_ip())
        self.local_ip_label.pack(side='left', padx=5)

        conn_frame = ttk.Frame(config_frame)
        conn_frame.pack(fill='x', pady=5)
        ttk.Label(conn_frame, text="Receiver IP:").pack(side='left', padx=5)
        self.receiver_ip_entry = ttk.Entry(conn_frame, width=15)
        self.receiver_ip_entry.pack(side='left', padx=5)
        ttk.Label(conn_frame, text="Port:").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.pack(side='left', padx=5)
        self.port_entry.insert(0, "5000")

        key_frame = ttk.Frame(config_frame)
        key_frame.pack(fill='x', pady=5)
        radio_frame = ttk.Frame(key_frame)
        radio_frame.pack(fill='x', pady=5)
        self.key_choice_var = tk.StringVar()
        self.key_choice_var.set("quantum")
        ttk.Radiobutton(radio_frame, text="Quantum Key", variable=self.key_choice_var,
                        value="quantum", command=self.toggle_key_fields).pack(side='left', padx=5)
        ttk.Radiobutton(radio_frame, text="Kyber Key", variable=self.key_choice_var,
                        value="kyber", command=self.toggle_key_fields).pack(side='left', padx=5)
        ttk.Radiobutton(radio_frame, text="Hybrid Key", variable=self.key_choice_var,
                        value="hybrid", command=self.toggle_key_fields).pack(side='left', padx=5)

        self.quantum_frame = ttk.Frame(key_frame)
        self.quantum_frame.pack(fill='x', pady=2)
        self.quantum_label = ttk.Label(self.quantum_frame, text="Quantum Key:")
        self.quantum_label.pack(side='left', padx=5)
        self.quantum_entry = ttk.Entry(self.quantum_frame, width=50, show="*")
        self.quantum_entry.pack(side='left', padx=5)
        self.quantum_copy_button = ttk.Button(self.quantum_frame, text="Copy", 
                                                command=lambda: self.copy_key(self.quantum_entry))
        self.quantum_copy_button.pack(side='left', padx=5)
        self.quantum_delete_button = ttk.Button(self.quantum_frame, text="Delete", 
                                                command=lambda: self.delete_key(self.quantum_entry))
        self.quantum_delete_button.pack(side='left', padx=5)

        self.kyber_frame = ttk.Frame(key_frame)
        self.kyber_frame.pack(fill='x', pady=2)
        self.kyber_label = ttk.Label(self.kyber_frame, text="Kyber Key:")
        self.kyber_label.pack(side='left', padx=5)
        self.kyber_entry = ttk.Entry(self.kyber_frame, width=50)
        self.kyber_entry.pack(side='left', padx=5)
        self.kyber_copy_button = ttk.Button(self.kyber_frame, text="Copy", 
                                            command=lambda: self.copy_key(self.kyber_entry))
        self.kyber_copy_button.pack(side='left', padx=5)
        self.kyber_delete_button = ttk.Button(self.kyber_frame, text="Delete", 
                                            command=lambda: self.delete_key(self.kyber_entry))
        self.kyber_delete_button.pack(side='left', padx=5)

        self.hybrid_frame = ttk.Frame(key_frame)
        self.hybrid_frame.pack(fill='x', pady=2)
        self.hybrid_label = ttk.Label(self.hybrid_frame, text="Hybrid Key:")
        self.hybrid_label.pack(side='left', padx=5)
        self.hybrid_entry = ttk.Entry(self.hybrid_frame, width=50)
        self.hybrid_entry.pack(side='left', padx=5)
        self.hybrid_copy_button = ttk.Button(self.hybrid_frame, text="Copy", 
                                            command=lambda: self.copy_key(self.hybrid_entry))
        self.hybrid_copy_button.pack(side='left', padx=5)
        self.hybrid_delete_button = ttk.Button(self.hybrid_frame, text="Delete", 
                                            command=lambda: self.delete_key(self.hybrid_entry))
        self.hybrid_delete_button.pack(side='left', padx=5)

        self.toggle_key_fields()

        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill='x', pady=5)
        self.connect_button = ttk.Button(button_frame, text="Connect", command=self.connect_to_receiver)
        self.connect_button.pack(side='left', padx=5)
        ttk.Button(button_frame, text="Refresh IP Status", command=self.refresh_vpn_status).pack(side='left', padx=5)
        
        self.send_file_button = ttk.Button(button_frame, text="Send File", command=self.send_file, state='disabled')
        self.send_file_button.pack(side='left', padx=5)
        
        self.save_logs_button = ttk.Button(button_frame, text="Save Performance Logs", command=self.save_performance_logs)
        self.save_logs_button.pack(side='left', padx=5)

        self.clear_chat_button = ttk.Button(button_frame, text="Clear Chat", command=self.clear_chat)
        self.clear_chat_button.pack(side='left', padx=5)

        self.end_chat_button = ttk.Button(button_frame, text="End Chat", command=self.end_chat, state='disabled')
        self.end_chat_button.pack(side='left', padx=5)

    def setup_chat_frame(self):
        chat_frame = ttk.Frame(self.window)
        chat_frame.pack(fill='both', padx=5, pady=5, expand=True)

        # self.chat_text = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD)
        # self.chat_text.pack(pady=5, fill='both', expand=True)
        self.chat_text = scrolledtext.ScrolledText(chat_frame, height=20, width=60, wrap=tk.WORD)
        self.chat_text.pack(pady=10, fill='both', expand=True)

        message_frame = ttk.Frame(chat_frame)
        message_frame.pack(fill='x', pady=5)

        self.message_entry = ttk.Entry(message_frame, font=("Helvetica", 14))
        self.message_entry.grid(row=0, column=0, sticky='ew', padx=5)
        self.message_entry.bind('<Return>', self.send_message)

        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message, state='disabled')
        self.send_button.grid(row=0, column=1, padx=5)

        message_frame.columnconfigure(0, weight=1)
        
    def copy_key(self, entry_widget=None):
        if entry_widget is None:
            entry_widget = self.get_active_key_entry()
        key = entry_widget.get()
        if key:
            self.window.clipboard_clear()
            self.window.clipboard_append(key)

    def delete_key(self, entry_widget=None):
        if entry_widget is None:
            entry_widget = self.get_active_key_entry()
        entry_widget.delete(0, tk.END)

    def toggle_key_fields(self):
        key_type = self.key_choice_var.get()
        if key_type == "quantum":
            self.quantum_entry.config(state="normal")
            self.kyber_entry.config(state="disabled")
            self.hybrid_entry.config(state="disabled")
            self.kyber_entry.delete(0, tk.END)
            self.hybrid_entry.delete(0, tk.END)
        elif key_type == "kyber":
            self.quantum_entry.config(state="disabled")
            self.kyber_entry.config(state="normal")
            self.hybrid_entry.config(state="disabled")
            self.quantum_entry.delete(0, tk.END)
            self.hybrid_entry.delete(0, tk.END)
        elif key_type == "hybrid":
            self.quantum_entry.config(state="disabled")
            self.kyber_entry.config(state="disabled")
            self.hybrid_entry.config(state="normal")
            self.quantum_entry.delete(0, tk.END)
            self.kyber_entry.delete(0, tk.END)

    def get_active_key_entry(self):
        key_type = self.key_choice_var.get()
        if key_type == "quantum":
            return self.quantum_entry
        elif key_type == "hybrid":
            return self.hybrid_entry
        else:
            return self.kyber_entry
        
    def generate_key_from_quantum_key(self, quantum_key):
        start_time = time.perf_counter()
        salt = b'quantum_secure_salt'
        key = PBKDF2(quantum_key.encode('utf-8'), salt, dkLen=32)
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        self.log_performance("key_generation_quantum", len(quantum_key), duration_ms, category="message")
        return key

    def generate_key_from_kyber_key(self, kyber_key):
        start_time = time.perf_counter()
        key = hashlib.sha256(kyber_key.encode()).digest()
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        self.log_performance("key_generation_kyber", len(kyber_key), duration_ms, category="message")
        return key
    
    def generate_key_from_hybrid_key(self, hybrid_key):
        start_time = time.perf_counter()
        try:
            if len(hybrid_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in hybrid_key):
                key = bytes.fromhex(hybrid_key)
            else:
                key = hashlib.sha256(hybrid_key.encode()).digest()
        except Exception:
            key = hashlib.sha256(hybrid_key.encode()).digest()
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        self.log_performance("key_generation_hybrid", len(hybrid_key), duration_ms, category="message")
        return key

    def connect_to_receiver(self):
        receiver_ip = self.receiver_ip_entry.get()
        key_type = self.key_choice_var.get()
        if key_type == "quantum":
            key = self.quantum_entry.get()
        elif key_type == "hybrid":
            key = self.hybrid_entry.get()
        else:
            key = self.kyber_entry.get()

        port = int(self.port_entry.get())

        if not receiver_ip or not key:
            messagebox.showerror("Error", "Please enter Receiver IP and Key")
            return

        try:
            start_time = time.perf_counter()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((receiver_ip, port))
            if key_type == "quantum":
                self.quantum_key = key
                self.quantum_key_hash = hashlib.sha256(key.encode()).hexdigest()
                self.symmetric_key = self.generate_key_from_quantum_key(key)
            elif key_type == "hybrid":
                self.hybrid_key = key
                self.symmetric_key = self.generate_key_from_hybrid_key(key)
            else:
                self.kyber_key = key
                self.symmetric_key = self.generate_key_from_kyber_key(key)

            key_to_send = (self.quantum_key_hash.encode('utf-8') if key_type == "quantum" 
                        else (self.hybrid_key.encode('utf-8') if key_type == "hybrid" 
                                else self.kyber_key.encode('utf-8')))
            self.socket.send(key_to_send)
            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000
            self.log_performance("connection_establishment", len(key), duration_ms,
                                additional_info=f"Connected to {receiver_ip}:{port}",
                                category="message")
            self.send_button.config(state='normal')
            self.send_file_button.config(state='normal')
            self.end_chat_button.config(state='normal')
            self.connect_button.config(state='disabled')
            self.insert_message(f"Connected to {receiver_ip}:{port} in {duration_ms:.2f}ms. Ready to chat.\n")
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def refresh_vpn_status(self):
        new_ip = self.get_local_ip()
        self.local_ip_label.config(text=new_ip)
        messagebox.showinfo("IP Status", f"Local IP refreshed: {new_ip}")

    def get_local_ip(self):
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except Exception:
            return "Unable to retrieve IP"

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
                self.insert_message("You have disconnected from the chat.\n")
        except Exception as e:
            messagebox.showerror("Disconnect Error", str(e))

    def encrypt_message(self, message, key, category="message", log_operation=True):
        start_time = time.perf_counter()
        if isinstance(message, bytes):
            message_bytes = message
        else:
            message_bytes = message.encode('utf-8')
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message_bytes)
        result = base64.b64encode(nonce + ciphertext + tag).decode('utf-8')
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        if log_operation:
            if category == "message" and isinstance(message, str) and ':' in message:
                parts = message.split(':', 1)
                if parts[0].isdigit():
                    actual_message_length = len(parts[1])
                else:
                    actual_message_length = len(message)
            else:
                actual_message_length = len(message) if isinstance(message, str) else len(message_bytes)
            self.log_performance("encrypt", len(message_bytes), duration_ms, category=category,
                                message_char_count=actual_message_length)
        return result

    def decrypt_message(self, ciphertext, key, category="message", log_operation=True):
        start_time = time.perf_counter()
        raw = base64.b64decode(ciphertext)
        nonce = raw[:16]
        ciphertext_part = raw[16:-16]
        tag = raw[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext_part, tag)
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        try:
            decrypted_str = decrypted.decode('utf-8')
            if category == "message" and ':' in decrypted_str:
                parts = decrypted_str.split(':', 1)
                if parts[0].isdigit():
                    char_count = len(parts[1])
                else:
                    char_count = len(decrypted_str)
            else:
                char_count = len(decrypted_str)
        except UnicodeDecodeError:
            decrypted_str = ""
            char_count = len(decrypted)
        if log_operation:
            self.log_performance("decrypt", len(raw), duration_ms, category=category, message_char_count=char_count)
        try:
            return decrypted.decode('utf-8')
        except UnicodeDecodeError:
            return decrypted

    def send_message(self, event=None):
        message = self.message_entry.get()
        if not message:
            return
        try:
            start_time = time.perf_counter()
            message_id = f"{int(start_time * 1000)}"
            message_with_id = f"{message_id}:{message}"
            encrypted_message = self.encrypt_message(message_with_id, self.symmetric_key)
            self.socket.send(encrypted_message.encode('utf-8'))
            self.message_send_times[message_id] = start_time
            self.insert_message(f"You: {message}\n")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def receive_messages(self):
        while True:
            try:
                data = self.socket.recv(16384)
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
                        self.insert_message("Invalid file header received.\n")
                        self.recv_buffer = ""
                        continue
                    _, file_name, data_length_str = parts
                    try:
                        data_length = int(data_length_str)
                    except ValueError:
                        self.insert_message("Invalid file length received.\n")
                        self.recv_buffer = ""
                        continue
                    total_length = newline_index + 1 + data_length
                    if len(self.recv_buffer) < total_length:
                        continue
                    encrypted_file = self.recv_buffer[newline_index+1:total_length]
                    self.recv_buffer = self.recv_buffer[total_length:]
                    file_dec_start = time.perf_counter()
                    try:
                        decrypted_file_content = self.decrypt_message(encrypted_file, self.symmetric_key, category="file", log_operation=False)
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
                            self.insert_message(f"File '{file_name}' decryption failed, and saving was skipped.\n")
                            continue
                    file_dec_end = time.perf_counter()
                    duration_ms = (file_dec_end - file_dec_start) * 1000
                    file_ext = os.path.splitext(file_name)[1] or "unknown"
                    self.log_performance("file_receive_decrypt", len(encrypted_file), duration_ms,
                                         additional_info=f"File: {file_name}",
                                         category="file",
                                         file_type=file_ext,
                                         decryption_type="AES-GCM")
                    save_path = filedialog.asksaveasfilename(
                        defaultextension="",
                        initialfile=file_name,
                        title="Save received file as"
                    )
                    if save_path:
                        with open(save_path, 'wb') as file:
                            file.write(file_content)
                        status = "decrypted" if is_decrypted else "encrypted"
                        self.insert_message(f"File saved as: {save_path} ({status})\n")
                    continue
                else:
                    if self.recv_buffer:
                        try:
                            recv_time = time.perf_counter()
                            decrypted_message = self.decrypt_message(self.recv_buffer, self.symmetric_key)
                            parts = decrypted_message.split(':', 1)
                            if len(parts) == 2 and parts[0].isdigit():
                                message_id, message_text = parts
                                if message_id in self.message_send_times:
                                    send_time = self.message_send_times.pop(message_id)
                                    rtt_ms = (recv_time - send_time) * 1000
                                    self.log_performance("message_round_trip", len(decrypted_message), rtt_ms, additional_info=f"ID:{message_id}", category="message")
                                    self.insert_message(f"Sender: {message_text}\n")
                                else:
                                    self.insert_message(f"Sender: {message_text}\n")
                            else:
                                self.insert_message(f"Sender: {decrypted_message}\n")
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
                                self.insert_message(f"[Encrypted]: {self.recv_buffer}\n")
                            else:
                                self.insert_message("Message rejected due to key mismatch.\n")
                        self.recv_buffer = ""
            except Exception as e:
                messagebox.showerror("Receive Error", str(e))
                break

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    sender = QuantumSecureSender()
    sender.run()
