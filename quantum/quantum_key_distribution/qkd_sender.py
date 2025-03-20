import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import random
import hashlib
from tkinter import filedialog
from matplotlib.lines import Line2D
import qiskit
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit_aer import AerSimulator
from qiskit import transpile
import threading
import numpy as np
from queue import Queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from time import perf_counter
import matplotlib
matplotlib.use('TkAgg')
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

class BB84SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BB84 Quantum Key Distribution - Sender (Alice)")
        self.root.geometry("800x600")
        
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill='both', expand=True)

        self.setup_auth_frame(main_frame)

        self.setup_input_frame(main_frame)

        self.setup_public_comparison_frame(main_frame)
        
        self.setup_output_frame(main_frame)
        
        self.queue = Queue()

        self.bob_measurements = None
        self.bob_bases = None
        self.sender_bits = None
        self.sender_bases = None
        self.final_key = None

        self.sent_key_hash = None
        self.received_key_hash = None

        self.current_circuit = None

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
        
        aes_key = derive_aes_key(psk)
        encrypted_sender_ip = encrypt_data(self.get_ip(), aes_key)
        
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
                    decrypted_receiver_ip = decrypt_data(encrypted_receiver_ip, aes_key)  # Decrypt received IP
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
        
        ttk.Label(conn_frame, text="Receiver IP:").pack(side='left', padx=5)
        self.host_entry = ttk.Entry(conn_frame, width=15)
        self.host_entry.pack(side='left', padx=5)
        
        ttk.Label(conn_frame, text="Eve IP (optional):").pack(side='left', padx=5)
        self.eve_entry = ttk.Entry(conn_frame, width=15)
        self.eve_entry.pack(side='left', padx=5)
        
        ttk.Label(conn_frame, text="Port:").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.pack(side='left', padx=5)
        self.port_entry.insert(0, "12345")
        
        qubit_frame = ttk.Frame(input_frame)
        qubit_frame.pack(fill='x', pady=5)
        
        ttk.Label(qubit_frame, text="Number of qubits:").pack(side='left', padx=5)
        self.n_qubits = ttk.Entry(qubit_frame, width=10)
        self.n_qubits.pack(side='left', padx=5)
        self.n_qubits.insert(0, "10")

        self.visualize_button = ttk.Button(qubit_frame, text="Quantum Circuits",
                                         command=self.show_quantum_circuit)
        self.visualize_button.pack(side='left', padx=5)
        self.visualize_button.config(state='disabled')

        mode_frame = ttk.Frame(input_frame)
        mode_frame.pack(fill='x', pady=5)
        
        ttk.Label(mode_frame, text="Generation mode:").pack(side='left', padx=5)
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

        ttk.Button(button_frame, text="Start Transmission", 
                  command=self.start_transmission).pack(side='left', padx=5)

        ttk.Button(button_frame, text="Clear Output",
                  command=self.clear_output).pack(side='left', padx=5)

        ttk.Button(button_frame, text="Refresh IP Status",
                  command=self.refresh_status).pack(side='left', padx=5)

        self.listening = False

        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill='x', pady=5)
    
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

    def start_listening(self):
        if not self.listening:
            try:
                host = '0.0.0.0'
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
                
                threading.Thread(target=self.listen_for_connection, daemon=True).start()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            self.stop_listening()
            
    def generate_quantum_random_bits(self, num_bits):
        num_qubits_per_chunk = 16
        total_key_length = num_bits
        key_binary = ''
        
        while len(key_binary) < total_key_length:
            qc = QuantumCircuit(num_qubits_per_chunk)
            for qubit in range(num_qubits_per_chunk):
                qc.h(qubit)
            qc.measure_all()

            self.current_circuit = qc
            # Enable the visualization button
            self.visualize_button.config(state='normal')
            
            backend = AerSimulator()
            compiled_circuit = transpile(qc, backend)
            job = backend.run(compiled_circuit, shots=1)
            result = job.result()
            counts = result.get_counts()
            random_chunk = list(counts.keys())[0]
            key_binary += random_chunk
        
        key_binary = key_binary[:total_key_length]
        return [int(bit) for bit in key_binary]

    def manual_input_dialog(self, n_bits):
        dialog = tk.Toplevel(self.root)
        dialog.title("Manual Input")
        dialog.geometry("300x400")
        dialog.transient(self.root)
        dialog.grab_set()
        sender_bits = []
        sender_bases = []
    
        def submit():
            try:
                for i in range(n_bits):
                    bit = int(bit_vars[i].get())
                    base = base_vars[i].get()
                    if bit not in [0, 1] or base not in ['+', 'x']:
                        raise ValueError
                    sender_bits.append(bit)
                    sender_bases.append(base)
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

        bit_vars = []
        base_vars = []
        for i in range(n_bits):
            frame = ttk.Frame(scrollable_frame)
            frame.pack(pady=5)
            
            ttk.Label(frame, text=f"Bit {i+1}:").pack(side='left')
            bit_var = tk.StringVar()
            ttk.Entry(frame, textvariable=bit_var, width=5).pack(side='left')
            bit_vars.append(bit_var)
            
            ttk.Label(frame, text="Base:").pack(side='left')
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
        
        return sender_bits, sender_bases if sender_bits else (None, None)

    def send_data(self, host, port, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                self.output.insert(tk.END, f"Attempting to connect to {host}:{port}\n")
                s.connect((host, port))
                self.output.insert(tk.END, f"Connected to {host}:{port}\n")
                s.sendall(json.dumps(data).encode())
                response = s.recv(4096).decode()
                return json.loads(response), True
        except ConnectionRefusedError:
            self.display_error(f"Connection refused by {host}:{port}")
            return None, False
        except Exception as e:
            self.display_error(f"Error connecting to {host}:{port}: {e}")
            return None, False

    from time import perf_counter

    def start_transmission(self):
        eve_ip = self.eve_entry.get().strip()
        if not eve_ip and not self.is_authenticated:
            messagebox.showerror("Error", "Please authenticate first")
            return
        try:
            self.current_circuit = None
            self.visualize_button.config(state='disabled')
            
            n_bits = int(self.n_qubits.get())
            if n_bits <= 0:
                raise ValueError("Number of qubits must be positive")
            
            receiver_ip = self.host_entry.get()
            if not receiver_ip:
                raise ValueError("Receiver IP is required")
                
            eve_ip = self.eve_entry.get().strip()
            port_eve = 12346
            port_receiver = int(self.port_entry.get())

            if self.mode_var.get() == "auto":
                sender_bits = self.generate_quantum_random_bits(n_bits)
                sender_bases = ['+' if b == 0 else 'x' 
                                for b in self.generate_quantum_random_bits(n_bits)]
            else:
                sender_bits, sender_bases = self.manual_input_dialog(n_bits)
                if not sender_bits:
                    return
            
            self.output.delete(1.0, tk.END)
            self.output.insert(tk.END, "Starting quantum transmission...\n\n")
            self.output.insert(tk.END, "Alice's Bits: " + str(sender_bits) + "\n")
            self.output.insert(tk.END, "Alice's Bases: " + str(sender_bases) + "\n\n")
            
            # Create a quantum circuit to encode Alice's qubits
            qr = QuantumRegister(n_bits, name='qr')
            cr = ClassicalRegister(n_bits, name='cr')
            qc = QuantumCircuit(qr, cr)
            
            for i in range(n_bits):
                if sender_bits[i] == 1:
                    qc.x(qr[i])  # Flip |0⟩ to |1⟩ if bit is 1
                
                if sender_bases[i] == 'x':
                    qc.h(qr[i])  # Apply Hadamard if using X basis
            
            self.current_circuit = qc

            circuit_ops = []
            for instruction in qc.data:
                gate_name = instruction.operation.name
                qubits = [qr.index(q) for q in instruction.qubits]
                circuit_ops.append({
                    'gate': gate_name,
                    'qubits': qubits
                })
            
            start_time = perf_counter()
            quantum_state = {
                'circuit_operations': circuit_ops,
                'n_bits': n_bits,
                'start_time': start_time
            }
            
            # Try Eve IP
            if eve_ip:
                response_data, eve_present = self.send_data(eve_ip, port_eve, quantum_state)
            else:
                eve_present = False
                response_data = None
                
            if not eve_present:
                self.output.insert(tk.END, "Direct connection to receiver (Eve not present)\n")
                response_data, success = self.send_data(receiver_ip, port_receiver, quantum_state)
                if not success:
                    self.display_error("Failed to connect to receiver")
                    return
            else:
                self.output.insert(tk.END, "Connected through Eve (Eve present)\n")
            
            if response_data and 'bob_bases' in response_data:
                elapsed = perf_counter() - start_time  
                self.output.insert(tk.END, f"\nTime from transmission start to receiver readiness: {elapsed:.6f} seconds.\n")

                basis_comparison = {
                    'sender_bases': sender_bases,
                    'phase': 'basis_comparison'
                }

                if eve_present:
                    basis_result, _ = self.send_data(eve_ip, port_eve, basis_comparison)
                else:
                    basis_result, _ = self.send_data(receiver_ip, port_receiver, basis_comparison)
                
                if basis_result and 'bob_measurements' in basis_result:
                    self.display_results(sender_bits, sender_bases,
                                        basis_result['bob_bases'],
                                        basis_result['bob_measurements'])
                else:
                    self.display_error("Invalid basis comparison result")
            else:
                self.display_error("No valid quantum measurement response received")
                    
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def stop_listening(self):
        if hasattr(self, 'server_socket'):
            self.server_socket.close()
        self.listening = False
        self.listen_button.config(text="Start Listening")
        self.output.insert(tk.END, "Stopped listening.\n")

    def listen_for_connection(self):
        try:
            while self.listening:
                try:
                    self.server_socket.settimeout(1)
                    
                    client_socket, addr = self.server_socket.accept()
                    self.output.insert(tk.END, f"\nConnected to {addr}\n")

                    data = client_socket.recv(16384).decode()
                    received_data = json.loads(data)
    
                    if 'request' in received_data and received_data['request'] == 'get_key':
                        key_hash = received_data.get('key_hash')
                        if key_hash:
                            self.received_key_hash = key_hash
                            response = {'status': 'received'}
                            self.output.insert(tk.END, f"\nReceived key hash: {key_hash}\n")
                        else:
                            response = {'status': 'error'}
                        
                        client_socket.sendall(json.dumps(response).encode())
                        client_socket.close()
    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.output.insert(tk.END, f"\nError in connection: {e}\n")
                    break
        except Exception as e:
            if self.listening:
                self.output.insert(tk.END, f"\nError in listening: {e}\n")
        finally:
            self.listening = False
            self.listen_button.config(text="Start Listening")

    def send_key(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showwarning("Warning", "Key cannot be empty")
            return
    
        receiver_ip = self.host_entry.get().strip()
        if not receiver_ip:
            messagebox.showwarning("Warning", "Receiver IP is required")
            return
    
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            self.sent_key_hash = key_hash
    
            port = int(self.port_entry.get())
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((receiver_ip, port))
                key_data = {'request': 'get_key', 'key_hash': key_hash}
                s.sendall(json.dumps(key_data).encode())

                response = s.recv(4096).decode()
                response_data = json.loads(response)
    
                if response_data.get('status') == 'received':
                    self.output.insert(tk.END, f"\nKey hash sent successfully to {receiver_ip}.\n")
                else:
                    self.output.insert(tk.END, f"\nError: Key hash was not acknowledged.\n")
        except Exception as e:
            self.display_error(f"Error sending key: {e}")
        
    def compare_keys(self):
        if not self.sent_key_hash:
            messagebox.showwarning("Warning", "No key hash sent.")
            return
        if not self.received_key_hash:
            messagebox.showwarning("Warning", "No key hash received.")
            return
    
        if self.sent_key_hash == self.received_key_hash:
            messagebox.showinfo("Key Comparison", "Keys match! No eavesdropping detected.")
        else:
            messagebox.showerror("Eavesdropping Alert!", "WARNING: Keys do not match! Possible eavesdropping detected!")
            self.output.insert(tk.END, "\n")
            self.output.insert(tk.END, "\n----------⚠️ WARNING: POSSIBLE EAVESDROPPING DETECTED!⚠️----------\n")
    
    def show_quantum_circuit(self):
        if self.current_circuit is None:
            messagebox.showwarning("Warning", "No quantum circuit available. Generate bits first.")
            return

        circuit_window = tk.Toplevel(self.root)
        circuit_window.title("Quantum Circuit Visualization")
        circuit_window.geometry("1000x600")

        notebook = ttk.Notebook(circuit_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: Circuit Visualization
        circuit_tab = ttk.Frame(notebook)
        notebook.add(circuit_tab, text="Circuit Diagram")

        circuit_frame = ttk.Frame(circuit_tab)
        circuit_frame.pack(fill='both', expand=True, padx=15, pady=5)

        h_scrollbar = ttk.Scrollbar(circuit_frame, orient='horizontal')
        v_scrollbar = ttk.Scrollbar(circuit_frame, orient='vertical')
        canvas = tk.Canvas(circuit_frame, 
                        xscrollcommand=h_scrollbar.set,
                        yscrollcommand=v_scrollbar.set)
        
        h_scrollbar.config(command=canvas.xview)
        v_scrollbar.config(command=canvas.yview)
        
        h_scrollbar.pack(side='bottom', fill='x')
        v_scrollbar.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)

        if isinstance(self.current_circuit, qiskit.circuit.quantumcircuit.QuantumCircuit):
            n_qubits = self.current_circuit.num_qubits
            n_gates = len(self.current_circuit.data)

            width = 8 
            height = max(7, n_qubits * 0.9)
            
            fig = plt.figure(figsize=(width, height), dpi=100)
            ax = fig.add_subplot(111)

            custom_style = {
                'backgroundcolor': '#F5F5F5',
                'linecolor': '#333333',
                'textcolor': '#000000',
                'gatefacecolor': ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c'],
                'gatetextcolor': 'white',
                'subfontsize': 12,
                'fontsize': 14,
                'creglinestyle': 'solid',
                'creglinecolor': '#FF6600',
                'displaytext': {
                    'CNOT': '⊕',
                    'X': '✕',
                    'H': 'H',
                    'SWAP': '⇄',
                    'Z': 'Z',
                    'S': 'S',
                    'T': 'T',
                    'RX': 'Rx',
                    'RY': 'Ry',
                    'RZ': 'Rz'
                }
            }

            self.current_circuit.draw(output='mpl', 
                                    ax=ax,
                                    scale=0.9,
                                    style=custom_style,
                                    fold=20,  
                                    plot_barriers=True, 
                                    initial_state=True,  
                                    with_layout=True)   

            title = f"Quantum Circuit: {self.current_circuit.name}\n"
            title += f"{n_qubits} Qubits | {len(self.current_circuit.data)} Operations | Depth: {self.current_circuit.depth()}"
            ax.set_title(title, fontsize=16, color='#2c3e50', pad=20)

            gate_types = set(instr.operation.name for instr in self.current_circuit.data)
            gate_desc = {
                'h': 'Hadamard (H): Creates superposition',
                'x': 'Pauli-X: Bit flip (NOT gate)',
                'z': 'Pauli-Z: Phase flip',
                'y': 'Pauli-Y: Combined X and Z',
                'cx': 'CNOT: Controlled-NOT',
                'measure': 'Measurement: Collapses state',
                'rx': 'RX: Rotation around X-axis',
                'ry': 'RY: Rotation around Y-axis',
                'rz': 'RZ: Rotation around Z-axis'
            }

            legend_text = "Gate Legend:\n\n"
            for gate in gate_types:
                if gate.lower() in gate_desc:
                    legend_text += f"• {gate_desc[gate.lower()]}\n"

            props = dict(boxstyle='round', facecolor='#f8f9fa', alpha=0.7)
            ax.text(0.98, 0.02, legend_text, transform=ax.transAxes, fontsize=10,
                    verticalalignment='bottom', horizontalalignment='right', bbox=props)

            gradient = np.linspace(0, 1, 100).reshape(-1, 1)
            gradient = np.repeat(gradient, 10, axis=1)
            ax.imshow(gradient, aspect='auto', extent=[-0.5, -0.3, -0.5, n_qubits+0.5], 
                    cmap='Blues', alpha=0.2, zorder=-1)

            plt.tight_layout()

            figure_canvas = FigureCanvasTkAgg(fig, master=canvas)
            figure_canvas.draw()
            figure_widget = figure_canvas.get_tk_widget()

            canvas_window = canvas.create_window(0, 0, anchor='nw', window=figure_widget)

            def update_scroll_region(event):
                canvas.configure(scrollregion=canvas.bbox("all"))
                
            figure_widget.bind("<Configure>", update_scroll_region)

            canvas.update_idletasks()
            canvas.configure(scrollregion=canvas.bbox("all"))
            
        # Tab 2: Circuit Information
        info_tab = ttk.Frame(notebook)
        notebook.add(info_tab, text="Circuit Information")

        left_frame = ttk.Frame(info_tab)
        right_frame = ttk.Frame(info_tab)
        left_frame.pack(side='left', fill='both', expand=True)
        right_frame.pack(side='right', fill='both', expand=True)

        info_text = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD)
        info_text.pack(fill='both', expand=True, padx=5, pady=5)

        info_text.tag_configure("header", font=("Arial", 12, "bold"), foreground="#2c3e50")
        info_text.tag_configure("subheader", font=("Arial", 11, "bold"), foreground="#3498db")
        info_text.tag_configure("normal", font=("Arial", 10), foreground="#333333")
        info_text.tag_configure("highlight", font=("Arial", 10, "bold"), foreground="#e74c3c")

        if isinstance(self.current_circuit, qiskit.circuit.quantumcircuit.QuantumCircuit):
            info_text.insert(tk.END, "QUANTUM CIRCUIT DETAILS\n\n", "header")
            info_text.insert(tk.END, f"Circuit Name: ", "subheader")
            info_text.insert(tk.END, f"{self.current_circuit.name}\n\n", "normal")
            
            info_text.insert(tk.END, "QUBIT INFORMATION\n", "subheader")
            info_text.insert(tk.END, f"Number of Qubits: {self.current_circuit.num_qubits}\n", "normal")
            info_text.insert(tk.END, f"Number of Classical Bits: {self.current_circuit.num_clbits}\n\n", "normal")
            
            info_text.insert(tk.END, "CIRCUIT COMPLEXITY\n", "subheader")
            info_text.insert(tk.END, f"Number of Gates/Operations: {len(self.current_circuit.data)}\n", "normal")
            info_text.insert(tk.END, f"Circuit Depth: {self.current_circuit.depth()}\n", "normal")

            info_text.insert(tk.END, f"Circuit Width: {self.current_circuit.width()}\n\n", "normal")

            info_text.insert(tk.END, "GATE DISTRIBUTION\n", "subheader")
            gate_counts = {}
            for instruction in self.current_circuit.data:
                gate_name = instruction.operation.name
                if gate_name in gate_counts:
                    gate_counts[gate_name] += 1
                else:
                    gate_counts[gate_name] = 1

            sorted_gates = sorted(gate_counts.items(), key=lambda x: x[1], reverse=True)
            for i, (gate, count) in enumerate(sorted_gates):
                tag = "highlight" if i == 0 else "normal"
                info_text.insert(tk.END, f"  {gate}: {count}\n", tag)

            info_text.insert(tk.END, "\nCIRCUIT PROPERTIES\n", "subheader")

            has_measurements = any(instr.operation.name == "measure" for instr in self.current_circuit.data)
            info_text.insert(tk.END, f"Has Measurements: {'Yes' if has_measurements else 'No'}\n", "normal")

            has_conditions = any(instr.operation.condition is not None for instr in self.current_circuit.data)
            info_text.insert(tk.END, f"Has Conditional Operations: {'Yes' if has_conditions else 'No'}\n", "normal")

            has_entanglement = any(len(instr.qubits) > 1 for instr in self.current_circuit.data)
            info_text.insert(tk.END, f"Has Entanglement Potential: {'Yes' if has_entanglement else 'No'}\n", "normal")

        visual_frame = ttk.Frame(right_frame)
        visual_frame.pack(fill='both', expand=True, padx=5, pady=5)

        if isinstance(self.current_circuit, qiskit.circuit.quantumcircuit.QuantumCircuit):
            fig_gate = plt.figure(figsize=(5, 4))
            ax_gate = fig_gate.add_subplot(111)

            gate_counts = {}
            for instruction in self.current_circuit.data:
                gate_name = instruction.operation.name
                if gate_name in gate_counts:
                    gate_counts[gate_name] += 1
                else:
                    gate_counts[gate_name] = 1

            labels = list(gate_counts.keys())
            sizes = list(gate_counts.values())
            colors = plt.cm.viridis(np.linspace(0, 1, len(labels)))
            
            ax_gate.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors,
                    wedgeprops={'edgecolor': 'w', 'linewidth': 1})
            ax_gate.set_title("Gate Distribution", fontsize=12)

            ax_gate.axis('equal')
            plt.tight_layout()

            gate_canvas = FigureCanvasTkAgg(fig_gate, master=visual_frame)
            gate_canvas.draw()
            gate_canvas.get_tk_widget().pack(fill='both', expand=True)
            
        
        # Tab 3:Bloch Sphere 
        bloch_tab = ttk.Frame(notebook)
        notebook.add(bloch_tab, text="Bloch Sphere")

        bloch_frame = ttk.Frame(bloch_tab)
        bloch_frame.pack(fill='both', expand=True)

        fig_bloch = plt.figure(figsize=(8, 8))
        ax_bloch = fig_bloch.add_subplot(111, projection='3d')

        theta = np.linspace(0, 2 * np.pi, 100)
        phi = np.linspace(0, np.pi, 100)

        x = np.outer(np.cos(theta), np.sin(phi))
        y = np.outer(np.sin(theta), np.sin(phi))
        z = np.outer(np.ones_like(theta), np.cos(phi))

        THETA, PHI = np.meshgrid(theta, phi, indexing='ij')
        norm_phi = (PHI - PHI.min()) / (PHI.max() - PHI.min())
        cmap = plt.cm.coolwarm
        facecolors = cmap(norm_phi)

        surf = ax_bloch.plot_surface(
            x, y, z, linewidth=0, facecolors=facecolors, alpha=0.3, antialiased=True
        )

        u, v = np.mgrid[0:2 * np.pi:20j, 0:np.pi:10j]
        x_grid = np.cos(u) * np.sin(v)
        y_grid = np.sin(u) * np.sin(v)
        z_grid = np.cos(v)
        ax_bloch.plot_wireframe(x_grid, y_grid, z_grid, color='gray', alpha=0.1)

        ax_bloch.plot([-1, 1], [0, 0], [0, 0], 'r-', lw=2, alpha=0.8)  # x-axis
        ax_bloch.plot([0, 0], [-1, 1], [0, 0], 'g-', lw=2, alpha=0.8)  # y-axis
        ax_bloch.plot([0, 0], [0, 0], [-1, 1], 'b-', lw=2, alpha=0.8)  # z-axis

        ax_bloch.text(1.1, 0, 0, r'$x$', fontsize=14, color='red', weight='bold')
        ax_bloch.text(0, 1.1, 0, r'$y$', fontsize=14, color='green', weight='bold')
        ax_bloch.text(0, 0, 1.1, r'$z$', fontsize=14, color='blue', weight='bold')

        ax_bloch.text(0, 0, 1.3, r'$|0\rangle$', fontsize=14, color='darkblue', weight='bold')
        ax_bloch.text(0, 0, -1.3, r'$|1\rangle$', fontsize=14, color='darkred', weight='bold')
        ax_bloch.text(1.3, 0, 0, r'$|+\rangle$', fontsize=14, color='darkorange', weight='bold')
        ax_bloch.text(-1.3, 0, 0, r'$|-\rangle$', fontsize=14, color='purple', weight='bold')
        ax_bloch.text(0, 1.3, 0, r'$|i\rangle$', fontsize=14, color='teal', weight='bold')
        ax_bloch.text(0, -1.3, 0, r'$|-i\rangle$', fontsize=14, color='magenta', weight='bold')

        ax_bloch.quiver(0, 0, 0, 0, 0, 1, color='blue', arrow_length_ratio=0.15, linewidth=2)
        ax_bloch.quiver(0, 0, 0, 0, 0, -1, color='red', arrow_length_ratio=0.15, linewidth=2)
        ax_bloch.quiver(0, 0, 0, 1, 0, 0, color='orange', arrow_length_ratio=0.15, linewidth=2)
        ax_bloch.quiver(0, 0, 0, 0.7, 0.5, 0.5, color='purple', arrow_length_ratio=0.15, linewidth=2)

        ax_bloch.set_box_aspect([1, 1, 1])
        ax_bloch.grid(False)
        ax_bloch.xaxis.pane.fill = False
        ax_bloch.yaxis.pane.fill = False
        ax_bloch.zaxis.pane.fill = False
        ax_bloch.xaxis.pane.set_edgecolor('w')
        ax_bloch.yaxis.pane.set_edgecolor('w')
        ax_bloch.zaxis.pane.set_edgecolor('w')
        ax_bloch.set_xticklabels([])
        ax_bloch.set_yticklabels([])
        ax_bloch.set_zticklabels([])

        ax_bloch.set_title("Interactive Bloch Sphere Representation", fontsize=16, color='#2c3e50', pad=20)

        angle_theta = np.pi / 4
        angle_phi = np.pi / 3
        x_point = np.sin(angle_phi) * np.cos(angle_theta)
        y_point = np.sin(angle_phi) * np.sin(angle_theta)
        z_point = np.cos(angle_phi)
        ax_bloch.scatter([x_point], [y_point], [z_point], color='gold', s=100, edgecolor='black', linewidth=1)
        ax_bloch.text(x_point * 1.1, y_point * 1.1, z_point * 1.1, "α|0⟩+β|1⟩", fontsize=10, color='black')

        legend_elements = [
            Line2D([0], [0], color='blue', lw=2, label='|0⟩ state'),
            Line2D([0], [0], color='red', lw=2, label='|1⟩ state'),
            Line2D([0], [0], color='orange', lw=2, label='|+⟩ state'),
            Line2D([0], [0], color='purple', lw=2, label='Superposition')
        ]
        ax_bloch.legend(handles=legend_elements, loc='upper right', fontsize=10)

        ax_bloch.text(0.5, 0.5, 0.7, "θ = polar angle", fontsize=10, color='navy')
        ax_bloch.text(-0.5, -0.5, 0.7, "φ = azimuthal angle", fontsize=10, color='darkgreen')

        circle_theta = np.linspace(0, 2 * np.pi, 100)
        circle_x = np.cos(circle_theta)
        circle_y = np.sin(circle_theta)
        circle_z = np.zeros_like(circle_theta)
        ax_bloch.plot(circle_x, circle_y, circle_z, 'y--', alpha=0.5)

        bloch_canvas = FigureCanvasTkAgg(fig_bloch, master=bloch_frame)
        bloch_canvas.draw()
        bloch_canvas.get_tk_widget().pack(fill='both', expand=True)

        controls_frame = ttk.Frame(bloch_tab)
        controls_frame.pack(fill='x', padx=10, pady=5)

        state_label = ttk.Label(controls_frame, text="Select Quantum State:")
        state_label.pack(side='left', padx=5)

        state_var = tk.StringVar()
        state_var.set("|0⟩")
        state_options = ["|0⟩", "|1⟩", "|+⟩", "|−⟩", "|+i⟩", "|−i⟩", "Custom"]
        state_menu = ttk.Combobox(controls_frame, textvariable=state_var, values=state_options, width=10)
        state_menu.pack(side='left', padx=5)

        rotation_label = ttk.Label(controls_frame, text="Rotation:")
        rotation_label.pack(side='left', padx=5)

        axis_var = tk.StringVar()
        axis_var.set("X")
        axis_options = ["X", "Y", "Z"]
        axis_menu = ttk.Combobox(controls_frame, textvariable=axis_var, values=axis_options, width=5)
        axis_menu.pack(side='left', padx=5)

        angle_label = ttk.Label(controls_frame, text="Angle (°):")
        angle_label.pack(side='left', padx=5)

        angle_var = tk.StringVar()
        angle_var.set("90")
        angle_entry = ttk.Entry(controls_frame, textvariable=angle_var, width=5)
        angle_entry.pack(side='left', padx=5)

        apply_button = ttk.Button(controls_frame, text="Apply", width=10)
        apply_button.pack(side='left', padx=10)

        reset_button = ttk.Button(controls_frame, text="Reset View", width=10)
        reset_button.pack(side='right', padx=10)
        
        # Tab 4: Measurement Probabilities
        if hasattr(self, 'sender_bits') and self.sender_bits and isinstance(self.current_circuit, QuantumCircuit):
            prob_tab = ttk.Frame(notebook)
            notebook.add(prob_tab, text="Measurement Probabilities")

            fig_prob = plt.figure(figsize=(10, 6))
            ax_prob = fig_prob.add_subplot(111)
            
            try:
                sim_circuit = self.current_circuit.copy()
                sim_circuit.remove_final_measurements(inplace=True)

                n_qubits = len(self.sender_bits)

                new_circ = QuantumCircuit(n_qubits, n_qubits)
                new_circ.compose(sim_circuit, qubits=range(n_qubits), inplace=True)
                new_circ.measure(range(n_qubits), range(n_qubits))

                backend = AerSimulator()
                compiled = transpile(new_circ, backend)
                result = backend.run(compiled, shots=1024).result()
                counts = result.get_counts()

                ax_prob.bar(counts.keys(), [count / 1024 for count in counts.values()])
                ax_prob.set_xlabel('Bit String')
                ax_prob.set_ylabel('Probability')
                ax_prob.set_title('Measurement Probabilities (1024 shots)')
                plt.setp(ax_prob.get_xticklabels(), rotation=45, ha='right')
                plt.tight_layout()

                prob_canvas = FigureCanvasTkAgg(fig_prob, master=prob_tab)
                prob_canvas.draw()
                prob_canvas.get_tk_widget().pack(fill='both', expand=True)
            except Exception as e:
                error_label = ttk.Label(prob_tab, text=f"Error simulating circuit: {str(e)}")
                error_label.pack(padx=10, pady=10)

        # Tab 5: Quantum State (Heatmap) Visualization
        state_tab = self.create_quantum_state_tab(notebook)
        notebook.add(state_tab, text="Quantum State")

        close_button = ttk.Button(circuit_window, text="Close", command=circuit_window.destroy)
        close_button.pack(pady=10)
        circuit_window.update_idletasks()
        circuit_window.minsize(circuit_window.winfo_width(), circuit_window.winfo_height())

    def plot_state_vector(self, ax=None, force_example=None):
        if not hasattr(self, 'sender_bits') or not self.sender_bits:
            return
            
        if ax is None:
            fig, ax = plt.subplots(figsize=(10, 6))

        n_qubits = len(self.sender_bits)

        try:
            if force_example is None:
                sim_circuit = self.current_circuit.copy()
                sim_circuit.remove_final_measurements(inplace=True)

                backend = AerSimulator(method='statevector')
                job = transpile(sim_circuit, backend)
                result = job.result()
                statevector = result.get_statevector()
            elif force_example == 'uniform':
                n_states = 2**n_qubits
                statevector = np.ones(n_states) / np.sqrt(n_states)
                phases = np.exp(1j * np.random.uniform(0, 2*np.pi, n_states))
                statevector = statevector * phases
            elif force_example == 'non-uniform':
                n_states = 2**n_qubits
                
                amplitudes = np.zeros(n_states)
                for i in range(n_states):
                    binary = format(i, f'0{n_qubits}b')
                    num_ones = binary.count('1')
                    amplitudes[i] = num_ones + 1
                    
                amplitudes += np.random.normal(0, 0.2, n_states)

                amplitudes = np.abs(amplitudes)

                amplitudes = amplitudes / np.sqrt(np.sum(amplitudes**2))

                phases = np.exp(1j * np.random.uniform(0, 2*np.pi, n_states))
                statevector = amplitudes * phases
        except Exception as e:
            print(f"Error generating statevector: {e}")
            n_states = 2**n_qubits
            statevector = np.ones(n_states) / np.sqrt(n_states)
            phases = np.exp(1j * np.random.uniform(0, 2*np.pi, n_states))
            statevector = statevector * phases

        probabilities = np.abs(statevector)**2
        phases = np.angle(statevector)

        is_uniform = np.allclose(probabilities, probabilities[0], rtol=1e-3)

        state_labels = [f"|{format(i, f'0{n_qubits}b')}⟩" for i in range(len(probabilities))]

        if n_qubits > 3:
            grid_cols = 2**(n_qubits // 2)
            grid_rows = 2**(n_qubits - n_qubits // 2)
            prob_grid = probabilities.reshape(grid_rows, grid_cols)

            mean_prob = np.mean(prob_grid)
            std_prob = np.std(prob_grid)
            
            if is_uniform:
                vmin = max(0, mean_prob * 0.99)
                vmax = min(1, mean_prob * 1.01)
                title_prefix = "Uniform Superposition - "
            else:
                vmin = max(0, 0) 
                vmax = min(1, mean_prob + 3 * std_prob)  
                title_prefix = "Non-uniform Quantum State - "

            from matplotlib.colors import PowerNorm

            norm = PowerNorm(gamma=0.7, vmin=vmin, vmax=vmax)

            heatmap = ax.imshow(prob_grid, cmap='viridis', norm=norm, interpolation='nearest')
            cbar = plt.colorbar(heatmap, ax=ax, label='Probability Amplitude')

            if is_uniform:
                cbar.ax.text(0.5, -0.1, "Enhanced contrast for\nuniform distribution", 
                            ha='center', va='top', transform=cbar.ax.transAxes, fontsize=8)
            
            x_labels = [f"|{format(i, f'0{n_qubits//2}b')}⟩" for i in range(grid_cols)]
            y_labels = [f"|{format(i, f'0{n_qubits-n_qubits//2}b')}⟩" for i in range(grid_rows)]
            ax.set_xticks(np.arange(grid_cols))
            ax.set_yticks(np.arange(grid_rows))
            ax.set_xticklabels(x_labels)
            ax.set_yticklabels(y_labels)
            plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

            for i in range(grid_rows):
                for j in range(grid_cols):
                    prob_val = prob_grid[i, j]
                    prob_text = f"{prob_val:.3f}"

                    norm_prob = (prob_val - vmin) / (vmax - vmin) if vmax > vmin else 0.5
                    text_color = "white" if norm_prob > 0.5 else "black"
                    
                    ax.text(j, i, prob_text, ha="center", va="center", color=text_color, fontsize=8)
                    
            ax.set_title(f"{title_prefix}Quantum State Probability Heatmap", fontsize=14, pad=20)
            ax.set_xlabel("Least Significant Qubits", fontsize=12)
            ax.set_ylabel("Most Significant Qubits", fontsize=12)
            
        else:
            norm = plt.Normalize(-np.pi, np.pi)
            colors = plt.cm.hsv(norm(phases))
            bars = ax.bar(state_labels, probabilities, color=colors)
            sm = plt.cm.ScalarMappable(cmap=plt.cm.hsv, norm=norm)
            sm.set_array([])
            cbar = plt.colorbar(sm, ax=ax)
            cbar.set_label('Phase (radians)', fontsize=12)
            
            for i, bar in enumerate(bars):
                height = bar.get_height()
                if height > 0.01:
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                            f'{probabilities[i]:.3f}', ha='center', va='bottom', fontsize=9)
            
            title_prefix = "Uniform Superposition - " if is_uniform else "Non-uniform Quantum State - "
            ax.set_title(f"{title_prefix}Quantum State Vector Visualization", fontsize=14, pad=20)
            ax.set_ylabel("Probability Amplitude", fontsize=12)
            ax.set_ylim(0, 1.1)

        ax.grid(True, linestyle='--', alpha=0.7)
        title_text = ax.get_title()
        ax.set_title("")
        plt.text(0.5, 1.05, title_text, horizontalalignment='center',
                verticalalignment='center', transform=ax.transAxes,
                fontsize=16, color='#2c3e50', fontweight='bold',
                bbox=dict(facecolor='white', alpha=0.8, edgecolor='none', boxstyle='round,pad=0.5'))

        legend_text = f"Total States: {len(probabilities)}\n"
        if is_uniform:
            legend_text += f"Uniform Distribution (p≈{probabilities[0]:.3f})\n"
        else:
            max_prob = np.max(probabilities)
            max_state = np.argmax(probabilities)
            max_state_bin = format(max_state, f'0{n_qubits}b')
            legend_text += f"Non-uniform Distribution\n"
            legend_text += f"Most likely: |{max_state_bin}⟩ (p={max_prob:.3f})\n"
        
        if n_qubits > 3:
            legend_text += "Visualization: 2D Heatmap\n"
            if is_uniform:
                legend_text += "Using enhanced contrast for uniform states"
            else:
                legend_text += "Brighter colors = Higher probability"
        else:
            legend_text += "Visualization: Color-coded bars\nBar height = Probability\nBar color = Phase angle"
        
        props = dict(boxstyle='round', facecolor='#f0f0f0', alpha=0.8)
        ax.text(0.02, 0.98, legend_text, transform=ax.transAxes, fontsize=9,
                verticalalignment='top', bbox=props)
        
        if n_qubits <= 3:
            phase_circle_ax = ax.inset_axes([0.75, 0.05, 0.2, 0.2], polar=True)
            theta_line = np.linspace(-np.pi, np.pi, 100)
            radii = np.ones_like(theta_line)
            norm_phase = plt.Normalize(-np.pi, np.pi)
            colors_phase = plt.cm.hsv(norm_phase(theta_line))
            phase_circle_ax.bar(theta_line, radii, width=np.pi/50, color=colors_phase, alpha=0.7)
            phase_circle_ax.set_theta_zero_location("E")
            phase_circle_ax.set_theta_direction(-1)
            phase_circle_ax.set_rticks([])
            phase_circle_ax.set_title("Phase Reference", fontsize=8)
        
        return ax

    def create_quantum_state_tab(self, notebook):
        state_tab = ttk.Frame(notebook)

        main_frame = ttk.Frame(state_tab)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.state_viz_frame = ttk.Frame(main_frame)
        self.state_viz_frame.pack(fill='both', expand=True)

        fig_state = plt.figure(figsize=(10, 6))
        ax_state = fig_state.add_subplot(111)
        self.plot_state_vector(ax_state)
        fig_state.patch.set_facecolor('#f5f5f5')
        ax_state.set_facecolor('#fafafa')
        plt.tight_layout()

        self.state_canvas = FigureCanvasTkAgg(fig_state, master=self.state_viz_frame)
        self.state_canvas.draw()
        self.state_canvas.get_tk_widget().pack(fill='both', expand=True)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=5)
        
        refresh_btn = ttk.Button(button_frame, text="Refresh State Visualization", 
                                command=lambda: self.refresh_state_visualization())
        refresh_btn.pack(side='right', padx=5)
        
        uniform_example_btn = ttk.Button(button_frame, text="Show Uniform Example", 
                                        command=lambda: self.show_example_state('uniform'))
        uniform_example_btn.pack(side='left', padx=5)
        
        non_uniform_example_btn = ttk.Button(button_frame, text="Show Non-uniform Example", 
                                            command=lambda: self.show_example_state('non-uniform'))
        non_uniform_example_btn.pack(side='left', padx=5)

        info_text = ("This visualization shows the quantum state vector of your circuit.\n"
                    "Uniform superposition states show all possible states with equal probability.\n"
                    "Non-uniform states show varying probabilities across different states.")
        info_label = ttk.Label(main_frame, text=info_text, background='#f0f0f0', 
                            wraplength=600, justify='left', padding=5)
        info_label.pack(fill='x', pady=5)
        
        return state_tab

    def refresh_state_visualization(self):
        if hasattr(self, 'state_canvas'):
            fig_state = plt.figure(figsize=(10, 6))
            ax_state = fig_state.add_subplot(111)
            self.plot_state_vector(ax_state)
            fig_state.patch.set_facecolor('#f5f5f5')
            ax_state.set_facecolor('#fafafa')
            plt.tight_layout()

            self.state_canvas.figure = fig_state
            self.state_canvas.draw()

    def show_example_state(self, example_type):
        """Show an example state visualization"""
        if hasattr(self, 'state_canvas'):
            fig_state = plt.figure(figsize=(10, 6))
            ax_state = fig_state.add_subplot(111)
            self.plot_state_vector(ax_state, force_example=example_type)
            fig_state.patch.set_facecolor('#f5f5f5')
            ax_state.set_facecolor('#fafafa')
            plt.tight_layout()

            self.state_canvas.figure = fig_state
            self.state_canvas.draw()
    
    def display_results(self, sender_bits, sender_bases, bob_bases, bob_measurements):
        self.sender_bits = sender_bits
        self.sender_bases = sender_bases
        self.bob_bases = bob_bases
        self.bob_measurements = bob_measurements
        kept_indices = [i for i in range(len(sender_bits)) 
                       if sender_bases[i] == bob_bases[i]]
        
        self.output.insert(tk.END, "\nBB84 Protocol Results\n")
        self.output.insert(tk.END, "-" * 70 + "\n")
        self.output.insert(tk.END, "Bit\tAlice's\tAlice's\tBob's\tBob's\tBit\n")
        self.output.insert(tk.END, "No.\tBit\tBasis\tBasis\tMeasure\tKept?\n")
        self.output.insert(tk.END, "-" * 70 + "\n")
        
        for i in range(len(sender_bits)):
            kept = "Yes" if i in kept_indices else "No"
            self.output.insert(tk.END, 
                             f"{i}\t{sender_bits[i]}\t{sender_bases[i]}\t"
                             f"{bob_bases[i]}\t{bob_measurements[i]}\t{kept}\n")

        sender_key = [sender_bits[i] for i in kept_indices]
        receiver_key = [bob_measurements[i] for i in kept_indices]
        
        final_key = ''.join(str(bit) for bit in sender_key)
        
        self.output.insert(tk.END, "-" * 70 + "\n")
        self.output.insert(tk.END, f"\nFinal shared key: {final_key}\n")
        
        self.final_key = final_key

        subset_length = max(1, len(final_key) * 20 // 100)
        key_subset = final_key[:subset_length]
        self.output.insert(tk.END, f"\nKey subset for verification: {key_subset}\n")
        
        matching_bases = len(kept_indices)
        self.output.insert(tk.END, f"\nTotal qubits: {len(sender_bits)}\n")
        self.output.insert(tk.END, f"Matching Bases: {matching_bases}\n")
        self.output.insert(tk.END, 
                          f"Key Generation Rate: {(matching_bases/len(sender_bits))*100:.2f}%\n")
    
    def display_error(self, error_message):
        self.output.insert(tk.END, f"\nError: {error_message}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = BB84SenderGUI(root)
    root.mainloop()
