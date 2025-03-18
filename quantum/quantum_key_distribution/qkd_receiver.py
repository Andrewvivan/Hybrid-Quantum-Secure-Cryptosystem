import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import random
import hashlib
import threading
from queue import Queue
import time
from time import perf_counter
import qiskit
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def derive_aes_key(psk):
    """Derive a 256-bit AES key from the PSK."""
    return hashlib.sha256(psk.encode()).digest()

def encrypt_data(data, key):
    """Encrypt data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-GCM."""
    raw = base64.b64decode(encrypted_data)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

class BB84ReceiverGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BB84 Quantum Key Distribution - Receiver (Bob)")
        self.root.geometry("800x600")

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill='both', expand=True)

        self.setup_auth_frame(main_frame)

        self.setup_input_frame(main_frame)

        self.setup_public_comparison_frame(main_frame)

        self.setup_output_frame(main_frame)

        self.sender_bits = None
        self.sender_bases = None
        self.bob_bases = None
        self.bob_measurements = None
        self.final_key = None

        self.queue = Queue()
        self.listening = False
        self.server_socket = None
        self.received_data = None
        self.client_socket = None
        self.last_client_ip = None

        self.sent_key_hash = None
        self.received_key_hash = None
        
    def get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            self.display_error(f"Error getting IP address: {e}")
            return None
    
    def setup_auth_frame(self, parent):
        auth_frame = ttk.LabelFrame(parent, text="Authentication", padding="10")
        auth_frame.pack(fill='x', padx=5, pady=5)

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

    def handle_auth_request(self, client_socket, received_data, addr):
        if hasattr(self, 'stored_psk_hash'):
            if received_data['psk_hash'] == self.stored_psk_hash:
                aes_key = derive_aes_key(self.psk_entry.get().strip())
                encrypted_sender_ip = received_data.get('sender_ip', '')

                try:
                    sender_ip = decrypt_data(encrypted_sender_ip, aes_key)  
                    self.last_client_ip = sender_ip

                    encrypted_receiver_ip = encrypt_data(self.get_ip(), aes_key) 

                    response = {
                        'status': 'authenticated',
                        'receiver_ip': encrypted_receiver_ip
                    }
                    self.root.after(0, lambda: self.update_auth_status(True, sender_ip))
                except Exception as e:
                    response = {'status': 'failed', 'error': str(e)}
                    self.root.after(0, lambda: self.update_auth_status(False))
            else:
                response = {'status': 'failed'}
                self.root.after(0, lambda: self.update_auth_status(False))
        else:
            response = {'status': 'not_ready'}
            self.root.after(0, lambda: self.output.insert(tk.END, "No PSK set on receiver\n"))

        client_socket.sendall(json.dumps(response).encode())
    
    def update_auth_status(self, success, sender_ip=None):
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


    def auth_success(self, sender_ip):
        self.is_authenticated = True
        status_text = f"Authenticated Sender at: {sender_ip}"
        self.auth_status_label.config(text=status_text, foreground="green")
        self.auth_button.config(state='disabled')
        self.psk_entry.config(state='disabled')
        self.output.insert(tk.END, f"\nAuthenticated with sender at {sender_ip}\n")

    def auth_failure(self):
        self.is_authenticated = False
        self.auth_status_label.config(text="Authentication Failed", foreground="red")
        self.auth_button.config(state='normal')
        self.psk_entry.config(state='normal')

    def setup_public_comparison_frame(self, parent):
        pcompare_frame = ttk.LabelFrame(parent, text="Public Comparison", padding="10")
        pcompare_frame.pack(fill='x', padx=5, pady=5)

        key_frame = ttk.Frame(pcompare_frame)
        key_frame.pack(fill='x', pady=5)

        ttk.Label(key_frame, text="Quantum Key:").pack(side='left', padx=5)
        self.key_entry = ttk.Entry(key_frame, width=30, show="*")
        self.key_entry.pack(side='left', padx=5, expand=True, fill='x')
 
        key_button_frame = ttk.Frame(pcompare_frame)
        key_button_frame.pack(fill='x', pady=5)
        
        ttk.Button(key_button_frame, text="Send Key", 
                command=self.send_key).pack(side='left', padx=5)
        
        ttk.Button(key_button_frame, text="Compare Key", 
                command=self.compare_keys).pack(side='left', padx=5)

    def setup_input_frame(self, parent):
        input_frame = ttk.LabelFrame(parent, text="Configuration", padding="10")
        input_frame.pack(fill='x', padx=5, pady=5)
        
        ip_frame = ttk.Frame(input_frame)
        ip_frame.pack(fill='x', pady=5)
        private_ip = self.get_ip()
        ttk.Label(ip_frame, text="Private IP:").pack(side='left', padx=5)
        self.ip_label = ttk.Label(ip_frame, text=private_ip if private_ip else "Not Connected")
        self.ip_label.pack(side='left', padx=5)

        conn_frame = ttk.Frame(input_frame)
        conn_frame.pack(fill='x', pady=5)
        
        ttk.Label(conn_frame, text="Listen on:").pack(side='left', padx=5)
        self.host_entry = ttk.Entry(conn_frame, width=15)
        self.host_entry.pack(side='left', padx=5)
        self.host_entry.insert(0, "0.0.0.0")  
        
        ttk.Label(conn_frame, text="Port:").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.pack(side='left', padx=5)
        self.port_entry.insert(0, "12345")

        mode_frame = ttk.Frame(input_frame)
        mode_frame.pack(fill='x', pady=5)
        
        ttk.Label(mode_frame, text="Measurement mode:").pack(side='left', padx=5)
        self.mode_var = tk.StringVar(value="auto")
        ttk.Radiobutton(mode_frame, text="Auto", variable=self.mode_var, 
                       value="auto").pack(side='left', padx=5)
        ttk.Radiobutton(mode_frame, text="Manual", variable=self.mode_var,
                       value="manual").pack(side='left', padx=5)

        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill='x', pady=5)
        
        self.listen_button = ttk.Button(button_frame, text="Start Listening",
                                      command=self.start_listening)
        self.listen_button.pack(side='left', padx=5)
        
        self.measure_button = ttk.Button(button_frame, text="Start Measuring",
                                       command=self.start_measuring, state='disabled')
        self.measure_button.pack(side='left', padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Output",
                                     command=self.clear_output)
        self.clear_button.pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Refresh IP Status",
                  command=self.refresh_status).pack(side='left', padx=5)

    def refresh_status(self):
        private_ip = self.get_ip()
        self.ip_label.config(text=private_ip if private_ip else "Not Connected")

    def setup_output_frame(self, parent):
        output_frame = ttk.LabelFrame(parent, text="Results", padding="10")
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.output = scrolledtext.ScrolledText(output_frame, height=20)
        self.output.pack(fill='both', expand=True)
    
    def clear_output(self):
        self.output.delete(1.0, tk.END)

    def compare_keys(self):
        if not self.sent_key_hash and not self.received_key_hash:
            messagebox.showwarning("Warning", "No keys available to compare")
            return
        
        if self.sent_key_hash == self.received_key_hash:
            messagebox.showinfo("Key Comparison", "Keys match! No eavesdropping detected.")
        else:
            messagebox.showerror("Eavesdropping Alert!", "WARNING: Keys do not match! Possible eavesdropping detected!")
            self.output.insert(tk.END, "\n")
            self.output.insert(tk.END,"\n----------⚠️ WARNING: POSSIBLE EAVESDROPPING DETECTED!⚠️----------\n")

    def start_listening(self):
        if not self.listening:
            try:
                host = self.host_entry.get()
                port = int(self.port_entry.get())
                
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((host, port))
                self.server_socket.listen()
                
                self.listening = True
                self.listen_button.config(text="Stop Listening")
                
                pvt_ip = self.get_ip()
                if pvt_ip:
                    self.output.insert(tk.END, f"Private IP: {pvt_ip}\n")
                self.output.insert(tk.END, f"Listening on port: {port}\n")
                self.output.insert(tk.END, "Waiting for incoming connections...\n")

                threading.Thread(target=self.listen_for_connection).start()
                
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
        self.measure_button.config(state='disabled')

    def start_measuring(self):
        if self.received_data and self.client_socket:
            try:
                quantum_state = self.received_data
                circuit_ops = quantum_state.get('circuit_operations')
                n_bits = quantum_state.get('n_bits')
                if not circuit_ops or not n_bits:
                    raise ValueError("Invalid quantum state data received")

                if self.mode_var.get() == "auto":
                    bob_bases = ['+' if random.randint(0, 1) == 0 else 'x' for _ in range(n_bits)]
                else:
                    bob_bases = self.manual_measurement_dialog(n_bits)
                    if not bob_bases: 
                        return

                chunk_size = 16
                bob_measurements = []

                for chunk_start in range(0, n_bits, chunk_size):
                    chunk_end = min(n_bits, chunk_start + chunk_size)
                    current_chunk_size = chunk_end - chunk_start

                    qc = QuantumCircuit(current_chunk_size, current_chunk_size)

                    for op in circuit_ops:
                        q_index = op.get('qubits', [None])[0]
                        if q_index is None:
                            continue
                        if chunk_start <= q_index < chunk_end:
                            adjusted_index = q_index - chunk_start
                            gate = op.get('gate')
                            if gate == 'x':
                                qc.x(adjusted_index)
                            elif gate == 'h':
                                qc.h(adjusted_index)

                    for i in range(current_chunk_size):
                        global_index = chunk_start + i
                        if bob_bases[global_index] == 'x':
                            qc.h(i)

                    qc.measure(range(current_chunk_size), range(current_chunk_size))

                    backend = AerSimulator()
                    compiled_circuit = transpile(qc, backend)
                    job = backend.run(compiled_circuit, shots=1)
                    result = job.result()
                    counts = result.get_counts()
                    measured_bitstring = list(counts.keys())[0]
                    measured_bitstring = measured_bitstring[::-1]
                    for bit in measured_bitstring:
                        bob_measurements.append(int(bit))

                self.output.insert(tk.END, f"\nBob's Bases: {bob_bases}\n")
                self.output.insert(tk.END, f"Bob's Measurements: {bob_measurements}\n")

                response_data = {
                    'bob_bases': bob_bases,
                    'bob_measurements': bob_measurements
                }
                self.client_socket.sendall(json.dumps(response_data).encode())

                self.bob_bases = bob_bases
                self.bob_measurements = bob_measurements

                self.received_data = None
                self.measure_button.config(state='disabled')
                
                if 'start_time' in quantum_state:
                    elapsed = perf_counter() - quantum_state['start_time']
                    self.output.insert(tk.END, f"\nTime from transmission start to measurement: {elapsed:.6f} seconds.\n")
            
            except Exception as e:
                self.display_error(f"Error during measurement: {e}")
                if self.client_socket:
                    self.client_socket.close()
                self.client_socket = None
        else:
            self.display_error("No data received or connection lost")
            self.measure_button.config(state='disabled')

    def listen_for_connection(self):
        try:
            while self.listening:
                try:
                    self.server_socket.settimeout(1)
                    client_socket, addr = self.server_socket.accept()

                    data = client_socket.recv(16384).decode()
                    received_data = json.loads(data)

                    if 'request' in received_data and received_data['request'] == 'authenticate':
                        self.handle_auth_request(client_socket, received_data, addr)
                        client_socket.close()  
                        continue  

                    if not self.is_authenticated:
                        client_socket.close()
                        self.root.after(0, lambda: self.output.insert(tk.END, "Rejected connection from unauthenticated sender\n"))
                        continue

                    self.client_socket = client_socket
                    self.last_client_ip = addr[0]

                    self.root.after(0, lambda: self.output.insert(tk.END, f"\nConnected to {addr}\n"))

                    if 'request' in received_data:
                        if received_data['request'] == 'get_key':
                            key_hash = received_data.get('key_hash')
                            if key_hash:
                                self.received_key_hash = key_hash
                                response = {'status': 'received'}
                                self.root.after(0, lambda: self.output.insert(tk.END, f"\nReceived key hash: {key_hash}\n"))
                            else:
                                response = {'status': 'error', 'message': 'Invalid key data'}

                            client_socket.sendall(json.dumps(response).encode())
                            client_socket.close()

                        else:
                            self.root.after(0, lambda: self.output.insert(tk.END, "Unknown request received.\n"))
                            client_socket.close()

                    elif 'sender_bases' in received_data:
                        sender_bases = received_data.get('sender_bases')
                        
                        if sender_bases and self.bob_bases and self.bob_measurements:
                            matching_indices = [i for i in range(len(sender_bases)) 
                                                if sender_bases[i] == self.bob_bases[i]]

                            final_measurements = [self.bob_measurements[i] for i in matching_indices]

                            final_key = ''.join(str(bit) for bit in final_measurements)
                            self.final_key = final_key

                            response_data = {
                                'bob_bases': self.bob_bases,
                                'bob_measurements': self.bob_measurements
                            }
                            
                            client_socket.sendall(json.dumps(response_data).encode())

                            self.root.after(0, lambda: self.display_results(
                                None,  
                                sender_bases, 
                                self.bob_bases, 
                                self.bob_measurements,
                                matching_indices
                            ))
                        else:
                            response = {'status': 'error', 'message': 'Missing data for basis comparison'}
                            client_socket.sendall(json.dumps(response).encode())
                        
                        client_socket.close()
                        self.client_socket = None

                    else:
                        self.received_data = received_data
                        start_time = self.received_data.get('start_time')
                        if start_time is not None:
                            elapsed = perf_counter() - start_time
                            self.elapsed_time = elapsed
                            self.root.after(0, lambda: self.output.insert(
                                tk.END, f"Quantum state received. Time taken: {elapsed:.6f} seconds. Start measuring.\n"))
                        else:
                            self.root.after(0, lambda: self.output.insert(
                                tk.END, "Quantum state received. Start measuring.\n"))
                        self.root.after(0, lambda: self.measure_button.config(state='normal'))

                except socket.timeout:
                    continue

        except Exception as e:
            if self.listening:
                self.root.after(0, lambda: self.display_error(f"Error in connection: {e}"))

        finally:
            if hasattr(self, 'server_socket'):
                self.server_socket.close()
            self.listening = False
            self.root.after(0, lambda: self.listen_button.config(text="Start Listening"))

    def manual_measurement_dialog(self, n_bits):
        dialog = tk.Toplevel(self.root)
        dialog.title("Manual Measurement")
        dialog.geometry("300x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        receiver_bases = []
        
        def submit():
            nonlocal receiver_bases
            try:
                receiver_bases = [base_vars[i].get() for i in range(n_bits)]
                if any(base not in ['+', 'x'] for base in receiver_bases):
                    raise ValueError
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid input")
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        base_vars = []
        for i in range(n_bits):
            frame = ttk.Frame(scrollable_frame)
            frame.pack(pady=5)
            
            ttk.Label(frame, text=f"Qubit {i+1} Base:").pack(side='left')
            base_var = tk.StringVar(value='+')
            ttk.Radiobutton(frame, text="+", variable=base_var, value='+').pack(side='left')
            ttk.Radiobutton(frame, text="x", variable=base_var, value='x').pack(side='left')
            base_vars.append(base_var)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill='x', padx=10, pady=10)
        submit_button = ttk.Button(button_frame, text="Submit", command=submit)
        submit_button.pack(pady=10)
        
        dialog.wait_window()
        return receiver_bases if receiver_bases else None
    
    def send_key(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showwarning("Warning", "Key cannot be empty")
            return

        if not hasattr(self, 'last_client_ip') or not self.last_client_ip:
            messagebox.showwarning("Warning", "No previous connection found. Start listening first.")
            return
        
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            self.sent_key_hash = key_hash
            
            port = int(self.port_entry.get())
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.last_client_ip, port))
                key_data = {'request': 'get_key', 'key_hash': key_hash}
                s.sendall(json.dumps(key_data).encode())

                s.settimeout(10)  
                try:
                    response = s.recv(4096).decode()
                    response_data = json.loads(response)
                    
                    if response_data.get('status') == 'received':
                        self.output.insert(tk.END, f"\nKey hash sent successfully to {self.last_client_ip}.\n")
                    else:
                        self.output.insert(tk.END, "\nError: Key hash was not acknowledged.\n")
                except socket.timeout:
                    self.output.insert(tk.END, "\nTimeout: No response from sender.\n")
        except Exception as e:
            self.output.insert(tk.END, f"\nError sending key: {e}\n")
            messagebox.showerror("Error", str(e))
    
    def check_queue(self):
        try:
            while True:
                method_name, args = self.queue.get_nowait()
                if method_name == "display_results":
                    self.display_results(*args)
                elif method_name == "error":
                    self.display_error(args)
                elif method_name == "status":
                    self.output.insert(tk.END, args)
        except:
            if self.listening:
                self.root.after(100, self.check_queue)

    def display_results(self, sender_bits, sender_bases, bob_bases, bob_measurements, kept_indices=None):
        show_sender_bits = sender_bits is not None

        if kept_indices is None and sender_bases and bob_bases:
            kept_indices = [i for i in range(len(sender_bases)) 
                           if sender_bases[i] == bob_bases[i]]
        
        self.output.insert(tk.END, "\nBB84 Protocol Results\n")
        self.output.insert(tk.END, "-" * 60 + "\n")

        header = "Bit\tAlice's\tBob's\tBob's\tBit\n"
        if show_sender_bits:
            header = "Bit\tAlice's\tAlice's\tBob's\tBob's\tBit\n"
            subheader = "No.\tBit\tBasis\tBasis\tMeasure\tKept?\n"
        else:
            header = "Bit\tAlice's\tBob's\tBob's\tBit\n"
            subheader = "No.\tBasis\tBasis\tMeasure\tKept?\n"
            
        self.output.insert(tk.END, header)
        self.output.insert(tk.END, subheader)
        self.output.insert(tk.END, "-" * 60 + "\n")
        
        for i in range(len(sender_bases)):
            kept = "Yes" if i in kept_indices else "No"
            if show_sender_bits:
                self.output.insert(tk.END, 
                                 f"{i}\t{sender_bits[i]}\t{sender_bases[i]}\t"
                                 f"{bob_bases[i]}\t{bob_measurements[i]}\t{kept}\n")
            else:
                self.output.insert(tk.END, 
                                 f"{i}\t{sender_bases[i]}\t"
                                 f"{bob_bases[i]}\t{bob_measurements[i]}\t{kept}\n")

        receiver_key = [bob_measurements[i] for i in kept_indices] if kept_indices else []
        final_key = ''.join(str(bit) for bit in receiver_key)
        
        self.output.insert(tk.END, "-" * 60 + "\n")
        self.output.insert(tk.END, f"\nFinal Shared key: {final_key}\n")
        
        self.final_key = final_key

        if final_key:
            subset_length = max(1, len(final_key) * 20 // 100)
            key_subset = final_key[:subset_length]
            self.output.insert(tk.END, f"\nKey subset for verification: {key_subset}\n")

        matching_bases = len(kept_indices) if kept_indices else 0
        total_qubits = len(sender_bases)
        self.output.insert(tk.END, f"\nTotal qubits: {total_qubits}\n")
        self.output.insert(tk.END, f"Matching Bases: {matching_bases}\n")
        if total_qubits > 0:
            self.output.insert(tk.END, 
                              f"Key Generation Rate: {(matching_bases/total_qubits)*100:.2f}%\n")
           
    def display_error(self, error_message):
        self.output.insert(tk.END, f"\nError: {error_message}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = BB84ReceiverGUI(root)
    root.mainloop()