import socket
import base64
import os
import threading
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_512
import hashlib
import hmac
import time
from datetime import datetime
import pandas as pd
from argon2.low_level import hash_secret_raw, Type
from kyber_wrapper768 import encapsulate

class QuantumSecureSender:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Advanced Quantum Secure Communication - Sender")
        width, height = 650, 750
        self.window.geometry(f"{width}x{height}")
        self.center_window(width, height)

        self.setup_configuration_frame()
        self.setup_chat_frame()

        self.socket = None
        self.symmetric_key = None
        self.hybrid_key = None
        self.show_encrypted = False

        self.recv_buffer = ""
        self.message_send_times = {}
        self.sequence_number = 0
        self.logs = []

    def center_window(self, width, height):
        self.window.update_idletasks()
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2) - 30
        y = max(y, 0)
        self.window.geometry(f"{width}x{height}+{x}+{y}")

    def display_message(self, message):
        timestamp = datetime.now().strftime("%I:%M:%S %p")
        current_yview = self.chat_text.yview()
        auto_scroll = (current_yview[1] == 1.0)
        self.chat_text.insert(tk.END, f"[{timestamp}] {message}\n")
        if auto_scroll:
            self.chat_text.see(tk.END)
        self.chat_text.update_idletasks()

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
        ttk.Label(key_frame, text="Hybrid Key:").pack(side='left', padx=5)
        self.hybrid_entry = ttk.Entry(key_frame, width=50)
        self.hybrid_entry.pack(side='left', padx=5)
        self.hybrid_entry.insert(0, "4e99fae59aa8a6d8ed051bf25b2c7d76b6ddbe7e70d8a988a2ab07a20943bde2b5a6ac4569fdbfc5d0373ed84877b7cf6a3d5f8450e6c1dec141d39134413f87")
        self.hybrid_copy_button = ttk.Button(key_frame, text="Copy", command=self.copy_key)
        self.hybrid_copy_button.pack(side='left', padx=5)
        self.hybrid_delete_button = ttk.Button(key_frame, text="Delete", command=self.delete_key)
        self.hybrid_delete_button.pack(side='left', padx=5)

        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill='x', pady=5)
        self.connect_button = ttk.Button(button_frame, text="Connect", command=self.connect_to_receiver)
        self.connect_button.pack(side='left', padx=5)
        ttk.Button(button_frame, text="Refresh IP Status", command=self.refresh_vpn_status).pack(side='left', padx=5)
        
        self.send_file_button = ttk.Button(button_frame, text="Send File", command=self.send_file, state='disabled')
        self.send_file_button.pack(side='left', padx=5)

        self.download_logs_button = ttk.Button(button_frame, text="Download Logs", command=self.download_logs)
        self.download_logs_button.pack(side='left', padx=5)

        self.clear_chat_button = ttk.Button(button_frame, text="Clear Chat", command=self.clear_chat)
        self.clear_chat_button.pack(side='left', padx=5)

        self.end_chat_button = ttk.Button(button_frame, text="End Chat", command=self.end_chat, state='disabled')
        self.end_chat_button.pack(side='left', padx=5)

    def setup_chat_frame(self):
        chat_frame = ttk.Frame(self.window)
        chat_frame.pack(fill='both', padx=5, pady=5, expand=True)

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

    def copy_key(self):
        key = self.hybrid_entry.get()
        if key:
            self.window.clipboard_clear()
            self.window.clipboard_append(key)

    def delete_key(self):
        self.hybrid_entry.delete(0, tk.END)

    def generate_key_from_hybrid_key(self, hybrid_key):
        try:
            if len(hybrid_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in hybrid_key):
                key = bytes.fromhex(hybrid_key)
            else:
                full_digest = hashlib.sha3_512(hybrid_key.encode()).digest()
                key = full_digest[:32]
        except Exception:
            full_digest = hashlib.sha3_512(hybrid_key.encode()).digest()
            key = full_digest[:32]
        return key

    def connect_to_receiver(self):
        receiver_ip = self.receiver_ip_entry.get()
        hybrid_key = self.hybrid_entry.get()
        port = int(self.port_entry.get())

        if not receiver_ip or not hybrid_key:
            messagebox.showerror("Error", "Please enter Receiver IP and Hybrid Key")
            return

        try:
            start_time = time.perf_counter()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((receiver_ip, port))
            self.hybrid_key = hybrid_key
            self.symmetric_key = self.generate_key_from_hybrid_key(hybrid_key)

            self.socket.send(hybrid_key.encode('utf-8'))
            
            response = self.socket.recv(2048).decode('utf-8')
            if response == "KEY_MISMATCH_REJECTED":
                messagebox.showerror("Authentication", "Key mismatch detected by receiver. Connection closed.")
                self.socket.close()
                return
            elif response == "KEY_MISMATCH_ACCEPTED":
                sender_decision = messagebox.askyesno("Key Mismatch",
                    "Keys mismatch. Still want to skip authentication and view encrypted data?")
                if sender_decision:
                    self.show_encrypted = True
                    self.socket.send("SENDER_KEY_MISMATCH_ACCEPTED".encode('utf-8'))
                    self.display_message("⚠️ KEY MISMATCH ACCEPTED! Proceeding with encrypted data")
                else:
                    self.socket.send("SENDER_KEY_MISMATCH_REJECTED".encode('utf-8'))
                    self.socket.close()
                    messagebox.showerror("Authentication", "Key mismatch. Connection closed.")
                    return
            elif response.startswith("SERVER_TIMESTAMP:"):
                self.first_msg = response
            else:
                messagebox.showerror("Authentication Error", "Unexpected response from receiver")
                self.socket.close()
                return

            if not self.show_encrypted:
                if not self.mutual_authenticate_client():
                    return
                if not self.perform_ephemeral_key_exchange():
                    return

            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000
            self.display_message(f"Connected to {receiver_ip}:{port} in {duration_ms:.2f}ms.")
            self.send_button.config(state='normal')
            self.send_file_button.config(state='normal')
            self.end_chat_button.config(state='normal')
            self.connect_button.config(state='disabled')
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def mutual_authenticate_client(self):
        if self.show_encrypted:
            return True
        try:
            self.display_message("Authenticating please wait...")
            start_time = time.perf_counter()
            server_timestamp_msg = self.first_msg if hasattr(self, 'first_msg') else self.socket.recv(2048).decode('utf-8')
            if not server_timestamp_msg.startswith("SERVER_TIMESTAMP:"):
                messagebox.showerror("Authentication Error", "Invalid timestamp challenge from server")
                self.socket.close()
                return False
            server_timestamp_str = server_timestamp_msg[len("SERVER_TIMESTAMP:"):]
            try:
                server_timestamp = int(server_timestamp_str)
            except:
                messagebox.showerror("Authentication Error", "Invalid server timestamp format")
                self.socket.close()
                return False

            if abs(int(time.time()) - server_timestamp) > 120:
                messagebox.showerror("Authentication Error", "Server timestamp is not fresh")
                self.socket.close()
                return False

            client_response = hmac.new(self.symmetric_key, str(server_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            self.socket.sendall(("CLIENT_RESPONSE:" + client_response).encode('utf-8'))

            client_timestamp = int(time.time())
            self.socket.sendall(("CLIENT_TIMESTAMP:" + str(client_timestamp)).encode('utf-8'))

            server_response_msg = self.socket.recv(2048).decode('utf-8')
            if not server_response_msg.startswith("SERVER_RESPONSE:"):
                messagebox.showerror("Authentication Error", "Invalid server response for timestamp challenge")
                self.socket.close()
                return False
            server_response = server_response_msg[len("SERVER_RESPONSE:"):]
            expected_response = hmac.new(self.symmetric_key, str(client_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            if server_response != expected_response:
                messagebox.showerror("Authentication Error", "Server authentication failed")
                self.socket.close()
                return False
            end_time = time.perf_counter()
            auth_duration = (end_time - start_time) * 1000
            self.display_message(f"✅ Authentication successful in {auth_duration:.2f}ms.")
            return True
        except Exception as e:
            messagebox.showerror("Authentication Error", str(e))
            self.socket.close()
            return False

    def perform_ephemeral_key_exchange(self):
        if self.show_encrypted:
            return True
        try:
            start_time = time.perf_counter()
            msg = self.socket.recv(4096).decode('utf-8').strip()
            if not msg.startswith("KYBER_EPHEMERAL:"):
                messagebox.showerror("Ephemeral Key Exchange Error", "Invalid Kyber public key message from server")
                self.socket.close()
                return False
            
            public_key_b64 = msg[len("KYBER_EPHEMERAL:"):]
            public_key = base64.b64decode(public_key_b64)
            ciphertext, shared_secret = encapsulate(public_key)
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
            response_msg = "KYBER_CIPHERTEXT:" + ciphertext_b64 + "\n"
            self.socket.sendall(response_msg.encode('utf-8'))

            self.symmetric_key = hash_secret_raw(
                secret=shared_secret,                
                salt=self.symmetric_key,             
                time_cost=4,                       
                memory_cost=102400,                 
                parallelism=8,                       
                hash_len=32,                         
                type=Type.ID                         
            )
            end_time = time.perf_counter()
            key_exchange_duration = (end_time - start_time) * 1000
            self.display_message(f"✅ Ephemeral Key Exchange successful in {key_exchange_duration:.2f}ms.")
            return True
        except Exception as e:
            messagebox.showerror("Ephemeral Key Exchange Error", str(e))
            self.socket.close()
            return False

    def send_file(self):
        if not self.socket:
            messagebox.showerror("Error", "Not connected")
            return

        file_path = filedialog.askopenfilename(title="Select file to send")
        if not file_path:
            return

        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            start_time = time.perf_counter()
            with open(file_path, 'rb') as file:
                file_content = file.read()
            
            b64_content = base64.b64encode(file_content).decode('utf-8')
            encrypted_file = self.encrypt_message(b64_content, self.symmetric_key)
            encrypted_file_bytes = encrypted_file.encode('utf-8')
            encryption_end_time = time.perf_counter()
            encryption_duration = (encryption_end_time - start_time) * 1000

            header = f"FILE:{file_name}:{len(encrypted_file_bytes)}\n"
            self.socket.sendall(header.encode('utf-8'))
            self.socket.sendall(encrypted_file_bytes)
            send_end_time = time.perf_counter()
            total_duration = (send_end_time - start_time) * 1000

            file_ext = os.path.splitext(file_name)[1] or "unknown"
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": "File Sent",
                "file_name": file_name,
                "file_size_bytes": file_size,
                "file_type": file_ext,
                "encryption_time_ms": encryption_duration,
                "transmission_time_ms": total_duration - encryption_duration,
                "total_time_ms": total_duration
            }
            self.logs.append(log_entry)
            self.display_message(f"You sent a file: {file_name} ({file_size/1024:.2f}KB) in {total_duration:.2f}ms")
        except Exception as e:
            messagebox.showerror("File Send Error", str(e))

    def download_logs(self):
        if not self.logs:
            messagebox.showinfo("Logs", "No logs to download")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            initialfile="sender_logs.xlsx",
            title="Save Logs"
        )
        if file_path:
            df = pd.DataFrame(self.logs)
            df.to_excel(file_path, index=False)
            messagebox.showinfo("Logs", f"Logs saved to {file_path}")

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
                self.socket.send("DISCONNECT".encode('utf-8'))
                self.socket.close()
                self.send_button.config(state='disabled')
                self.send_file_button.config(state='disabled')
                self.end_chat_button.config(state='disabled')
                self.connect_button.config(state='normal')
                self.display_message("You have disconnected from the chat.")
        except Exception as e:
            messagebox.showerror("Disconnect Error", str(e))

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
        ciphertext_part = raw[16:-16]
        tag = raw[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext_part, tag).decode('utf-8')

    def send_message(self, event=None):
        message = self.message_entry.get()
        if not message:
            return
        try:
            timestamp = int(time.time())
            message_with_seq = f"{self.sequence_number}:{timestamp}:{message}"
            encrypted_message = self.encrypt_message(message_with_seq, self.symmetric_key)
            self.socket.send(encrypted_message.encode('utf-8'))
            self.message_send_times[str(self.sequence_number)] = time.perf_counter()
            self.display_message(f"You: {message}")
            self.sequence_number += 1
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
                        self.display_message("Invalid file header received.")
                        self.recv_buffer = ""
                        continue
                    _, file_name, data_length_str = parts
                    try:
                        data_length = int(data_length_str)
                    except ValueError:
                        self.display_message("Invalid file length received.")
                        self.recv_buffer = ""
                        continue
                    total_length = newline_index + 1 + data_length
                    if len(self.recv_buffer) < total_length:
                        continue
                    encrypted_file = self.recv_buffer[newline_index+1:total_length]
                    self.recv_buffer = self.recv_buffer[total_length:]
                    file_dec_start = time.perf_counter()
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
                            self.display_message(f"File '{file_name}' decryption failed, and saving was skipped.")
                            continue
                    file_dec_end = time.perf_counter()
                    decryption_duration = (file_dec_end - file_dec_start) * 1000
                    file_size = len(encrypted_file)
                    file_ext = os.path.splitext(file_name)[1] or "unknown"
                    
                    log_entry = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "event": "File Received",
                        "file_name": file_name,
                        "file_size_bytes": file_size,
                        "file_type": file_ext,
                        "decryption_time_ms": decryption_duration
                    }
                    self.logs.append(log_entry)

                    save_choice = messagebox.askyesno("File Received", f"File received! {file_name} what to save it?")
                    if save_choice:
                        save_path = filedialog.asksaveasfilename(
                            defaultextension="",
                            initialfile=file_name,
                            title="Save received file as"
                        )
                        if save_path:
                            with open(save_path, 'wb') as file:
                                file.write(file_content)
                            status = "decrypted" if is_decrypted else "encrypted"
                            self.display_message(f"File saved as: {save_path} ({status})")
                        else:
                            self.display_message(f"File '{file_name}' was not saved.")
                    else:
                        self.display_message(f"File '{file_name}' received but not saved.")
                    continue
                else:
                    if self.recv_buffer:
                        try:
                            recv_time = time.perf_counter()
                            decrypted_message = self.decrypt_message(self.recv_buffer, self.symmetric_key)
                            parts = decrypted_message.split(":", 2)
                            if len(parts) == 3 and parts[0].isdigit():
                                seq = int(parts[0])
                                if seq != self.sequence_number:
                                    self.display_message("Message sequence number mismatch. Possible replay attack.")
                                    self.sequence_number = seq + 1
                                else:
                                    self.sequence_number += 1
                                if str(seq) in self.message_send_times:
                                    send_time = self.message_send_times.pop(str(seq))
                                    rtt_ms = (recv_time - send_time) * 1000
                                    log_entry = {
                                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                        "event": "Message Round Trip",
                                        "message": parts[2],
                                        "round_trip_time_ms": rtt_ms
                                    }
                                    self.logs.append(log_entry)
                                self.display_message(f"Receiver: {parts[2]}")
                            else:
                                self.display_message(f"Receiver: {decrypted_message}")
                        except Exception:
                            if self.show_encrypted:
                                self.display_message(f"[Receiver]: {self.recv_buffer}")
                            else:
                                self.display_message("Message rejected due to key mismatch.")
                        self.recv_buffer = ""
            except Exception as e:
                messagebox.showerror("Receive Error", str(e))
                break

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    sender = QuantumSecureSender()
    sender.run()