import socket
import json
import random
import time
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit_aer import AerSimulator
import gc
import sys

class BB84Sender:
    def __init__(self):
        self.bob_measurements = None
        self.bob_bases = None
        self.sender_bits = None
        self.sender_bases = None
        self.final_key = None
        self.n_qubits = 300

        self.bits_basis_gen_time = 0
        self.quantum_state_tx_time = 0
        self.basis_comparison_time = 0
        self.total_protocol_time = 0
        self.key_throughput = 0

    def generate_quantum_random_bits(self, num_bits):
        gc.collect()
        start_time = time.perf_counter()
        
        num_qubits_per_chunk = 16
        total_key_length = num_bits
        key_binary = ''

        while len(key_binary) < total_key_length:
            qc = QuantumCircuit(num_qubits_per_chunk)
            for qubit in range(num_qubits_per_chunk):
                qc.h(qubit)
            qc.measure_all()

            backend = AerSimulator()
            compiled_circuit = transpile(qc, backend)
            job = backend.run(compiled_circuit, shots=1)
            result = job.result()
            counts = result.get_counts()
            random_chunk = list(counts.keys())[0][::-1]
            key_binary += random_chunk

        key_binary = key_binary[:total_key_length]
        end_time = time.perf_counter()
        self.bits_basis_gen_time = (end_time - start_time) * 1_000_000  
        return [int(bit) for bit in key_binary]

    def send_data(self, host, port, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"Attempting to connect to {host}:{port}")
                s.connect((host, port))
                print(f"Connected to {host}:{port}")

                gc.collect()

                if 'circuit_operations' in data:
                    data['is_quantum_state'] = True
                    tx_start_time = time.perf_counter()
                    s.sendall(json.dumps(data).encode())

                    ack = s.recv(1024).decode()
                    tx_end_time = time.perf_counter()
                    
                    if json.loads(ack).get('received'):
                        self.quantum_state_tx_time = (tx_end_time - tx_start_time) * 1_000_000

                    response = s.recv(16384).decode()
                else:
                    s.sendall(json.dumps(data).encode())
                    response = s.recv(16384).decode()
                
                return json.loads(response), True
        except Exception as e:
            print(f"Connection failed: {e}")
            return None, False

    def start_transmission(self, receiver_ip, port):
        try:
            protocol_start_time = time.perf_counter()
            
            n_bits = self.n_qubits
            sender_bits = self.generate_quantum_random_bits(n_bits)
            sender_bases = ['+' if b == 0 else 'x' for b in self.generate_quantum_random_bits(n_bits)]

            self.sender_bits = sender_bits
            self.sender_bases = sender_bases

            print("Starting quantum transmission...")
            print("Alice's Bits: " + ''.join(str(b) for b in sender_bits))
            print("Alice's Bases: " + ''.join(sender_bases))

            qr = QuantumRegister(n_bits, name='qr')
            cr = ClassicalRegister(n_bits, name='cr')
            qc = QuantumCircuit(qr, cr)

            for i in range(n_bits):
                if sender_bits[i] == 1:
                    qc.x(qr[i])
                if sender_bases[i] == 'x':
                    qc.h(qr[i])

            circuit_ops = []
            for instruction in qc.data:
                gate_name = instruction.operation.name
                qubits = [qr.index(q) for q in instruction.qubits]
                circuit_ops.append({
                    'gate': gate_name,
                    'qubits': qubits
                })

            quantum_state = {
                'circuit_operations': circuit_ops,
                'n_bits': n_bits
            }

            response_data, success = self.send_data(receiver_ip, port, quantum_state)
            if not success:
                return

            if response_data and 'bob_bases' in response_data:
                self.bob_bases = response_data['bob_bases']
                self.bob_measurements = response_data['bob_measurements']

                basis_comparison = {
                    'sender_bases': sender_bases
                }

                gc.collect()
                basis_start_time = time.perf_counter()
                kept_indices = [i for i in range(len(self.sender_bits)) if self.sender_bases[i] == self.bob_bases[i]]
                basis_end_time = time.perf_counter()
                self.basis_comparison_time = (basis_end_time - basis_start_time) * 1_000_000  

                if self.basis_comparison_time > 0:
                    self.key_throughput = (len(kept_indices) / self.basis_comparison_time)  
                
                basis_result, _ = self.send_data(receiver_ip, port, basis_comparison)

                if basis_result and 'bob_measurements' in basis_result:
                    protocol_end_time = time.perf_counter()
                    self.total_protocol_time = (protocol_end_time - protocol_start_time) * 1_000_000
                    
                    self.display_results(sender_bits, sender_bases,
                                         basis_result['bob_bases'],
                                         basis_result['bob_measurements'])
                    print("\nProtocol completed successfully. Exiting...")
                else:
                    print("Invalid basis comparison result")
            else:
                print("No valid quantum measurement response received")
        except ValueError as e:
            print(f"Error: {e}")

    def display_results(self, sender_bits, sender_bases, bob_bases, bob_measurements):
        kept_indices = [i for i, b in enumerate(sender_bases) if b == bob_bases[i]]

        print("\nBB84 Protocol Results")
        print("-" * 70)
        print("Bit\tAlice's\tAlice's\tBob's\tBob's\tBit")
        print("No.\tBit\tBasis\tBasis\tMeasure\tKept?")
        print("-" * 70)

        for i in range(len(sender_bits)):
            kept = "Yes" if i in kept_indices else "No"
            print(f"{i}\t{sender_bits[i]}\t{sender_bases[i]}\t"
                  f"{bob_bases[i]}\t{bob_measurements[i]}\t{kept}")

        sender_key = [sender_bits[i] for i in kept_indices]
        final_key = ''.join(str(bit) for bit in sender_key)
        self.final_key = final_key

        print("-" * 70)
        print(f"\nFinal shared key: {final_key}")
        print(f"Total qubits: {len(sender_bits)}")
        print(f"Matching Bases: {len(kept_indices)}")
        print(f"Key Generation Rate: {(len(kept_indices) / len(sender_bits)) * 100:.2f}%")

        print("\n======= SENDER BENCHMARKS =======")
        print(f"Bits & Basis Generation Time: {self.bits_basis_gen_time:.2f} microseconds")
        print(f"Quantum State Transmission Time: {self.quantum_state_tx_time:.2f} microseconds")
        print(f"Basis Comparison Time: {self.basis_comparison_time:.2f} microseconds")
        print(f"Key Generation Throughput: {self.key_throughput:.2f} bits/microsecond")
        print(f"Total Protocol Time: {self.total_protocol_time:.2f} microseconds")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python s1.py <receiver_ip>")
        sys.exit(1)
    
    receiver_ip = sys.argv[1] 
    sender = BB84Sender()
    print("BB84 Quantum Key Distribution - Sender (Alice)")
    print("=============================================")
    port = 12345
    sender.start_transmission(receiver_ip, port)