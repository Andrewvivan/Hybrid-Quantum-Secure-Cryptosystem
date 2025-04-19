import socket
import json
import random
import threading
import time
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
import gc
import argparse

class BB84Receiver:
    def __init__(self):
        self.bob_bases = None
        self.bob_measurements = None
        self.final_key = None
        self.listening = False
        self.server_socket = None
        self.received_data = None
        self.client_socket = None
        self.last_client_ip = None
        # Benchmarking attributes
        self.state_receiving_time = 0
        self.state_measuring_time = 0
        self.basis_comparison_time = 0
        self.key_throughput = 0
        self.total_protocol_time = 0
        self.protocol_start_time = None
        self.quantum_data_received_time = None
        # For benchmarking
        self.iteration_complete = threading.Event()
        self.reset_needed = False

    def get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"Error getting IP address: {e}")
            return None

    def start_listening(self, port):
        if not self.listening:
            try:
                host = '0.0.0.0'
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((host, port))
                self.server_socket.listen()
                self.listening = True
                ip = self.get_ip()
                if ip:
                    print(f"Receiver running on Private IP: {ip}")
                print(f"Listening on port {port}...")
                
                # Clear any previous event status
                self.iteration_complete.clear()
                
                # Start listener in a separate thread
                self.listener_thread = threading.Thread(target=self.listen_for_connection, daemon=True)
                self.listener_thread.start()
                return True
            except Exception as e:
                print(f"Error starting listener: {e}")
                return False
        else:
            return True

    def stop_listening(self):
        if self.server_socket:
            self.server_socket.close()
        self.listening = False
        print("Stopped listening.")

    def reset_for_next_iteration(self):
        """Reset the receiver state for the next iteration"""
        self.bob_bases = None
        self.bob_measurements = None
        self.final_key = None
        self.received_data = None
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        self.client_socket = None
        self.state_receiving_time = 0
        self.state_measuring_time = 0 
        self.basis_comparison_time = 0
        self.key_throughput = 0
        self.total_protocol_time = 0
        self.protocol_start_time = None
        self.reset_needed = False
        gc.collect()
        
    def listen_for_connection(self):
        try:
            while self.listening:
                try:
                    self.server_socket.settimeout(1)
                    
                    # Reset state if needed from previous iteration
                    if self.reset_needed:
                        self.reset_for_next_iteration()
                    
                    # Accept connection
                    client, addr = self.server_socket.accept()
                    self.last_client_ip = addr[0]
                    
                    # Run garbage collection and wait for data
                    gc.collect()
                    
                    # Receive data - start timing when we actually receive data
                    receiving_start_time = time.perf_counter()
                    data = client.recv(16384).decode()
                    receiving_end_time = time.perf_counter()
                    
                    # Parse the data
                    msg = json.loads(data)
                    
                    # Check if this is quantum state data
                    if msg.get('is_quantum_state'):
                        self.protocol_start_time = receiving_start_time
                        self.state_receiving_time = (receiving_end_time - receiving_start_time) * 1_000_000  # Convert to microseconds
                        # Send acknowledgment of receipt before processing
                        client.sendall(json.dumps({'received': True}).encode())

                    # Check if we're receiving basis comparison data
                    if 'sender_bases' in msg and self.bob_bases and self.bob_measurements:
                        sb = msg['sender_bases']
                        
                        # Measure basis comparison time
                        gc.collect()
                        basis_start_time = time.perf_counter()
                        kept_indices = [i for i, b in enumerate(sb) if b == self.bob_bases[i]]
                        basis_end_time = time.perf_counter()
                        self.basis_comparison_time = (basis_end_time - basis_start_time) * 1_000_000  # Convert to microseconds
                        
                        # Calculate key throughput
                        if self.basis_comparison_time > 0:
                            self.key_throughput = (len(kept_indices) / self.basis_comparison_time)
                        
                        # Generate final key (but don't display it)
                        final_key_gen_start = time.perf_counter()
                        final_key = ''.join(str(self.bob_measurements[i]) for i in kept_indices)
                        self.final_key = final_key
                        final_key_gen_end = time.perf_counter()
                        
                        # Include the key generation time in the measurement time
                        self.state_measuring_time += (final_key_gen_end - final_key_gen_start) * 1_000_000
                        
                        # Send the response with measurement data
                        client.sendall(json.dumps({
                            'bob_bases': self.bob_bases,
                            'bob_measurements': self.bob_measurements
                        }).encode())

                        # Calculate total protocol time
                        protocol_end_time = time.perf_counter()
                        if self.protocol_start_time is not None:
                            self.total_protocol_time = (protocol_end_time - self.protocol_start_time) * 1_000_000  # Convert to microseconds

                        print("Protocol iteration completed.")
                        
                        # Mark this iteration as complete and ready for reset
                        self.reset_needed = True
                        self.iteration_complete.set()
                        
                        client.close()
                        self.client_socket = None
                        continue

                    self.client_socket = client
                    self.received_data = msg
                    print("Quantum state received. Measuring...")
                    self.measure_quantum_state()

                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error in connection handler: {e}")
                    if self.client_socket:
                        self.client_socket.close()
                        self.client_socket = None
        finally:
            if self.server_socket:
                self.server_socket.close()
            self.listening = False
            print("Listening stopped")

    def measure_quantum_state(self):
        if not self.received_data or not self.client_socket:
            print("No data received or connection lost.")
            return

        try:
            # Start timing the quantum state measurement
            gc.collect()
            measure_start_time = time.perf_counter()
            
            qs = self.received_data
            ops = qs.get('circuit_operations')
            n = qs.get('n_bits')
            if not ops or not n:
                raise ValueError("Invalid quantum state data")

            bb = ['+' if random.getrandbits(1) == 0 else 'x' for _ in range(n)]

            measurements = []
            chunk = 16
            for start in range(0, n, chunk):
                end = min(n, start + chunk)
                size = end - start
                qc = QuantumCircuit(size, size)

                for op in ops:
                    qi = op.get('qubits', [None])[0]
                    if qi is None or not (start <= qi < end):
                        continue
                    idx = qi - start
                    if op.get('gate') == 'x':
                        qc.x(idx)
                    elif op.get('gate') == 'h':
                        qc.h(idx)

                for i in range(size):
                    if bb[start + i] == 'x':
                        qc.h(i)

                qc.measure(range(size), range(size))
                backend = AerSimulator()
                tc = transpile(qc, backend)
                res = backend.run(tc, shots=1).result()
                bits = list(res.get_counts().keys())[0][::-1]
                measurements.extend(int(b) for b in bits)
            
            # End timing the quantum state measurement
            measure_end_time = time.perf_counter()
            self.state_measuring_time = (measure_end_time - measure_start_time) * 1_000_000  # Convert to microseconds

            self.client_socket.sendall(json.dumps({
                'bob_bases': bb,
                'bob_measurements': measurements
            }).encode())

            self.bob_bases = bb
            self.bob_measurements = measurements
            self.received_data = None

        except Exception as e:
            print(f"Error during measurement: {e}")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None

    def get_benchmark_data(self):
        return {
            "state_receiving_time": self.state_receiving_time,
            "state_measuring_time": self.state_measuring_time,
            "basis_comparison_time": self.basis_comparison_time,
            "key_throughput": self.key_throughput,
            "total_protocol_time": self.total_protocol_time
        }

def run_receiver_benchmark(port=12345, iterations=10):
    print("BB84 Quantum Key Distribution - Receiver (Bob)")
    print("==============================================")
    print(f"Preparing to run {iterations} benchmark iterations...")
    
    # Initialize receiver
    receiver = BB84Receiver()
    
    # Start listening
    if not receiver.start_listening(port):
        print("Failed to start listening. Exiting.")
        return
    
    # Variables to store accumulated benchmark data
    total_state_receiving_time = 0
    total_state_measuring_time = 0
    total_basis_comparison_time = 0
    total_key_throughput = 0
    total_protocol_time = 0
    
    # Counter for successful iterations
    successful_iterations = 0
    
    try:
        for i in range(iterations):
            print(f"\nWaiting for iteration {i+1}/{iterations}...")
            
            # Wait for the current iteration to complete
            receiver.iteration_complete.wait(timeout=120)  # 2 minute timeout
            
            if receiver.iteration_complete.is_set():
                # Get benchmark data for this iteration
                benchmark_data = receiver.get_benchmark_data()
                
                # Accumulate data
                total_state_receiving_time += benchmark_data["state_receiving_time"]
                total_state_measuring_time += benchmark_data["state_measuring_time"]
                total_basis_comparison_time += benchmark_data["basis_comparison_time"]
                total_key_throughput += benchmark_data["key_throughput"]
                total_protocol_time += benchmark_data["total_protocol_time"]
                
                successful_iterations += 1
                
                # Reset for next iteration
                receiver.iteration_complete.clear()
                receiver.reset_for_next_iteration()
                
                print(f"Completed iteration {i+1}")
            else:
                print(f"Timeout waiting for iteration {i+1}. Continuing...")
    
    except KeyboardInterrupt:
        print("\nBenchmarking interrupted.")
    finally:
        # Stop listening
        receiver.stop_listening()
        
        # Calculate averages if there were any successful iterations
        if successful_iterations > 0:
            avg_state_receiving_time = total_state_receiving_time / successful_iterations
            avg_state_measuring_time = total_state_measuring_time / successful_iterations
            avg_basis_comparison_time = total_basis_comparison_time / successful_iterations
            avg_key_throughput = total_key_throughput / successful_iterations
            avg_protocol_time = total_protocol_time / successful_iterations
            
            # Print average benchmark results
            print("\n======= RECEIVER AVERAGE BENCHMARKS ({} iterations) =======".format(successful_iterations))
            print(f"Avg Quantum State Receiving Time: {avg_state_receiving_time:.2f} microseconds")
            print(f"Avg Quantum State Measurement Time: {avg_state_measuring_time:.2f} microseconds")
            print(f"Avg Basis Comparison Time: {avg_basis_comparison_time:.2f} microseconds")
            print(f"Avg Key Generation Throughput: {avg_key_throughput:.2f} bits/microsecond")
            print(f"Avg Total Protocol Time: {avg_protocol_time:.2f} microseconds")
        else:
            print("No successful iterations. Cannot calculate average benchmarks.")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description='BB84 Quantum Key Distribution - Receiver (Bob)')
    parser.add_argument('--port', type=int, default=12345, help='Port number (default: 12345)')
    parser.add_argument('--iterations', type=int, default=10, help='Number of iterations for benchmarking (default: 10)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Run benchmark with specified parameters
    run_receiver_benchmark(args.port, args.iterations)