import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import random
import threading
from queue import Queue
import time
from time import perf_counter

class BB84EveGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BB84 Quantum Key Distribution - Interceptor (Eve)")
        self.root.geometry("800x600")

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill='both', expand=True)

        self.setup_input_frame(main_frame)

        self.setup_output_frame(main_frame)

        self.queue = Queue()
        self.listening = False
        self.server_socket = None
        
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
        self.eve_host_entry = ttk.Entry(conn_frame, width=15)
        self.eve_host_entry.pack(side='left', padx=5)
        self.eve_host_entry.insert(0, "0.0.0.0") 
        
        ttk.Label(conn_frame, text="Eve's Port:").pack(side='left', padx=5)
        self.eve_port_entry = ttk.Entry(conn_frame, width=10)
        self.eve_port_entry.pack(side='left', padx=5)
        self.eve_port_entry.insert(0, "12346")

        receiver_frame = ttk.Frame(input_frame)
        receiver_frame.pack(fill='x', pady=5)
        
        ttk.Label(receiver_frame, text="Receiver IP:").pack(side='left', padx=5)
        self.receiver_host_entry = ttk.Entry(receiver_frame, width=15)
        self.receiver_host_entry.pack(side='left', padx=5)
        
        ttk.Label(receiver_frame, text="Receiver Port:").pack(side='left', padx=5)
        self.receiver_port_entry = ttk.Entry(receiver_frame, width=10)
        self.receiver_port_entry.pack(side='left', padx=5)
        self.receiver_port_entry.insert(0, "12345")

        mode_frame = ttk.Frame(input_frame)
        mode_frame.pack(fill='x', pady=5)
        
        ttk.Label(mode_frame, text="Interception mode:").pack(side='left', padx=5)
        self.mode_var = tk.StringVar(value="auto")
        ttk.Radiobutton(mode_frame, text="Auto", variable=self.mode_var, 
                       value="auto").pack(side='left', padx=5)
        ttk.Radiobutton(mode_frame, text="Manual", variable=self.mode_var,
                       value="manual").pack(side='left', padx=5)

        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill='x', pady=5)
        
        self.listen_button = ttk.Button(button_frame, text="Start Intercepting",
                                      command=self.start_intercepting)
        self.listen_button.pack(side='left', padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Output",
                                     command=self.clear_output)
        self.clear_button.pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Refresh Status",
                  command=self.refresh_status).pack(side='left', padx=5)
    
    def refresh_status(self):
        private_ip = self.get_ip()
        self.ip_label.config(text=private_ip if private_ip else "Not Connected")

    def setup_output_frame(self, parent):
        output_frame = ttk.LabelFrame(parent, text="Interception Results", padding="10")
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.output = scrolledtext.ScrolledText(output_frame, height=20)
        self.output.pack(fill='both', expand=True)
    
    def clear_output(self):
        self.output.delete(1.0, tk.END)
    
    def get_measurement_outcome(self, alice_bit, alice_basis, eve_basis):
        if alice_basis == eve_basis:
            return alice_bit, True
        else:
            return random.randint(0, 1), False

    def manual_measurement_dialog(self, n_bits):
        dialog = tk.Toplevel(self.root)
        dialog.title("Manual Measurements")
        dialog.geometry("300x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        eve_bases = []
        
        def submit():
            try:
                for i in range(n_bits):
                    base = base_vars[i].get()
                    if base not in ['+', 'x']:
                        raise ValueError
                    eve_bases.append(base)
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
            
            ttk.Label(frame, text=f"Qubit {i+1} basis:").pack(side='left')
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
        return eve_bases if eve_bases else None
    
    def start_intercepting(self):
        if not self.listening:
            try:
                eve_host = self.eve_host_entry.get()
                eve_port = int(self.eve_port_entry.get())
                
                pvt_ip = self.get_ip()
                if not pvt_ip:
                    raise ValueError("No IP connection detected")

                receiver_host = self.receiver_host_entry.get()
                if not receiver_host:
                    raise ValueError("Receiver IP is required")
                
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((eve_host, eve_port))
                self.server_socket.listen()
                
                self.listening = True
                self.listen_button.config(text="Stop Intercepting")
                
                self.output.insert(tk.END, f"Private IP: {pvt_ip}\n")
                self.output.insert(tk.END, f"Listening on port: {eve_port}\n")
                self.output.insert(tk.END, "Waiting for transmission to intercept...\n")

                threading.Thread(target=self.intercept_transmission).start()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            self.stop_intercepting()

    def stop_intercepting(self):
        if self.server_socket:
            self.server_socket.close()
        self.listening = False
        self.listen_button.config(text="Start Intercepting")
        self.output.insert(tk.END, "Stopped intercepting.\n")
    
    def display_results(self, eve_bases, eve_measurements, matched_bases):
        self.output.insert(tk.END, "\nInterception Results:\n")
        self.output.insert(tk.END, "-" * 60 + "\n")
        self.output.insert(tk.END, "Bit\tEve's\tEve's\tBasis\n")
        self.output.insert(tk.END, "No.\tBasis\tMeasure\tMatched?\n")
        self.output.insert(tk.END, "-" * 60 + "\n")
        
        for i in range(len(eve_measurements)):
            self.output.insert(tk.END, 
                             f"{i}\t{eve_bases[i]}\t{eve_measurements[i]}\t"
                             f"{'Yes' if matched_bases[i] else 'No'}\n")

        matching_bases = sum(matched_bases)
        total_qubits = len(eve_measurements)
        self.output.insert(tk.END, "-" * 60 + "\n")
        self.output.insert(tk.END, f"\nTotal qubits intercepted: {total_qubits}\n")
        self.output.insert(tk.END, f"Correct bases guessed: {matching_bases}\n")
        self.output.insert(tk.END, 
                          f"Success rate: {(matching_bases/total_qubits)*100:.2f}%\n")

    def intercept_transmission(self):
        try:
            while self.listening:
                sender_conn, sender_addr = self.server_socket.accept()
                self.output.insert(tk.END, f"\nIntercepted connection from {sender_addr}\n")

                receiver_host = self.receiver_host_entry.get()
                receiver_port = int(self.receiver_port_entry.get())
                receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.output.insert(tk.END, f"Attempting to connect to receiver at {receiver_host}:{receiver_port}\n")
                receiver_socket.connect((receiver_host, receiver_port))
                self.output.insert(tk.END, "Connected to receiver\n")
                
                data = sender_conn.recv(16384).decode()
                received_json = json.loads(data)

                if 'phase' in received_json and received_json['phase'] == 'basis_comparison':
                    self.output.insert(tk.END, "Intercepted basis comparison message.\n")
                    receiver_socket.sendall(json.dumps(received_json).encode())
                    receiver_response = receiver_socket.recv(4096).decode()
                    sender_conn.sendall(receiver_response.encode())

                elif 'circuit_operations' in received_json and 'n_bits' in received_json:
                    n_bits = received_json['n_bits']
                    circuit_ops = received_json['circuit_operations']

                    sender_bits = []
                    sender_bases = []
                    for i in range(n_bits):
                        ops_for_i = [op for op in circuit_ops if i in op['qubits']]
                        if not ops_for_i:
                            s_bit, s_basis = 0, '+'
                        elif len(ops_for_i) == 1:
                            op = ops_for_i[0]
                            if op['gate'] == 'x':
                                s_bit, s_basis = 1, '+'
                            elif op['gate'] == 'h':
                                s_bit, s_basis = 0, 'x'
                            else:
                                s_bit, s_basis = 0, '+'
                        elif len(ops_for_i) >= 2:
                            s_bit, s_basis = 1, 'x'
                        sender_bits.append(s_bit)
                        sender_bases.append(s_basis)

                    if self.mode_var.get() == "auto":
                        eve_bases = [random.choice(['+', 'x']) for _ in range(n_bits)]
                    else:
                        eve_bases = self.manual_measurement_dialog(n_bits)
                        if not eve_bases:
                            sender_conn.close()
                            receiver_socket.close()
                            continue
                    
                    eve_measurements = []
                    matched_bases = []
                    for i in range(n_bits):
                        if eve_bases[i] == sender_bases[i]:
                            m_bit = sender_bits[i]
                            matched = True
                        else:
                            m_bit = random.randint(0, 1)
                            matched = False
                        eve_measurements.append(m_bit)
                        matched_bases.append(matched)

                    self.root.after(0, self.display_results, eve_bases, eve_measurements, matched_bases)

                    new_circuit_ops = []
                    for i in range(n_bits):
                        if eve_bases[i] == '+':
                            if eve_measurements[i] == 1:
                                new_circuit_ops.append({'gate': 'x', 'qubits': [i]})
                        elif eve_bases[i] == 'x':
                            if eve_measurements[i] == 0:
                                new_circuit_ops.append({'gate': 'h', 'qubits': [i]})
                            else:
                                new_circuit_ops.append({'gate': 'x', 'qubits': [i]})
                                new_circuit_ops.append({'gate': 'h', 'qubits': [i]})
                    
                    new_quantum_state = {
                        'circuit_operations': new_circuit_ops,
                        'n_bits': n_bits,
                        'start_time': perf_counter()  
                    }

                    receiver_socket.sendall(json.dumps(new_quantum_state).encode())
                    receiver_response = receiver_socket.recv(4096).decode()
                    sender_conn.sendall(receiver_response.encode())
                
                else:
                    receiver_socket.sendall(data.encode())
                    receiver_response = receiver_socket.recv(4096).decode()
                    sender_conn.sendall(receiver_response.encode())
                
                sender_conn.close()
                receiver_socket.close()
        except Exception as e:
            if self.listening:
                self.output.insert(tk.END, f"\nError during interception: {str(e)}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = BB84EveGUI(root)
    root.mainloop()