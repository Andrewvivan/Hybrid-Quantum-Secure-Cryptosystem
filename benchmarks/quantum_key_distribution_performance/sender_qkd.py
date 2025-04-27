import socket
import json
import random
import time
import sys
import argparse
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit_aer import AerSimulator
import gc

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
                if 'circuit_operations' in data:
                    print(f"Connecting to receiver at {host}:{port}")
                s.connect((host, port))
                if 'circuit_operations' in data:
                    print(f"Connected to receiver")

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
                return False

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
                
                basis_result, success = self.send_data(receiver_ip, port, basis_comparison)
                if not success:
                    return False

                if basis_result and 'bob_measurements' in basis_result:
                    protocol_end_time = time.perf_counter()
                    self.total_protocol_time = (protocol_end_time - protocol_start_time) * 1_000_000  
                    print("Protocol iteration completed successfully.")
                    return True
                else:
                    print("Invalid basis comparison result")
                    return False
            else:
                print("No valid quantum measurement response received")
                return False
        except ValueError as e:
            print(f"Error: {e}")
            return False

    def get_benchmark_data(self):
        return {
            "bits_basis_gen_time": self.bits_basis_gen_time,
            "quantum_state_tx_time": self.quantum_state_tx_time,
            "basis_comparison_time": self.basis_comparison_time,
            "key_throughput": self.key_throughput,
            "total_protocol_time": self.total_protocol_time
        }

def run_sender_benchmark(receiver_ip, port=12345, iterations=10):
    print("BB84 Quantum Key Distribution - Sender (Alice)")
    print("=============================================")
    print(f"Running {iterations} iterations to benchmark performance...")

    total_bits_basis_gen_time = 0
    total_quantum_state_tx_time = 0
    total_basis_comparison_time = 0
    total_key_throughput = 0
    total_protocol_time = 0

    successful_iterations = 0
    
    for i in range(iterations):
        print(f"\nIteration {i+1}/{iterations}")
        sender = BB84Sender()
        success = sender.start_transmission(receiver_ip, port)
        
        if success:
            benchmark_data = sender.get_benchmark_data()

            total_bits_basis_gen_time += benchmark_data["bits_basis_gen_time"]
            total_quantum_state_tx_time += benchmark_data["quantum_state_tx_time"]
            total_basis_comparison_time += benchmark_data["basis_comparison_time"]
            total_key_throughput += benchmark_data["key_throughput"]
            total_protocol_time += benchmark_data["total_protocol_time"]
            
            successful_iterations += 1

            time.sleep(2)
        else:
            print(f"Iteration {i+1} failed. Skipping this data point.")

    if successful_iterations > 0:
        avg_bits_basis_gen_time = total_bits_basis_gen_time / successful_iterations
        avg_quantum_state_tx_time = total_quantum_state_tx_time / successful_iterations
        avg_basis_comparison_time = total_basis_comparison_time / successful_iterations
        avg_key_throughput = total_key_throughput / successful_iterations
        avg_protocol_time = total_protocol_time / successful_iterations

        print("\n======= SENDER AVERAGE BENCHMARKS ({} iterations) =======".format(successful_iterations))
        print(f"Avg Bits & Basis Generation Time: {avg_bits_basis_gen_time:.2f} microseconds")
        print(f"Avg Quantum State Transmission Time: {avg_quantum_state_tx_time:.2f} microseconds")
        print(f"Avg Basis Comparison Time: {avg_basis_comparison_time:.2f} microseconds")
        print(f"Avg Key Generation Throughput: {avg_key_throughput:.2f} bits/microsecond")
        print(f"Avg Total Protocol Time: {avg_protocol_time:.2f} microseconds")
    else:
        print("No successful iterations. Cannot calculate average benchmarks.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='BB84 Quantum Key Distribution - Sender (Alice)')
    parser.add_argument('receiver_ip', type=str, help='IP address of the receiver')
    parser.add_argument('--port', type=int, default=12345, help='Port number (default: 12345)')
    parser.add_argument('--iterations', type=int, default=10, help='Number of iterations for benchmarking (default: 10)')

    args = parser.parse_args()

    run_sender_benchmark(args.receiver_ip, args.port, args.iterations)