import socket
import json
import random
import threading
import time
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
import gc

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
        self.state_receiving_time = 0
        self.state_measuring_time = 0
        self.basis_comparison_time = 0
        self.key_throughput = 0
        self.total_protocol_time = 0
        self.protocol_start_time = None
        self.quantum_data_received_time = None

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
                    print(f"Private IP: {ip}")
                print(f"Listening on port {port}...")
                
                threading.Thread(target=self.listen_for_connection, daemon=True).start()
            except Exception as e:
                print(f"Error: {e}")
        else:
            self.stop_listening()

    def stop_listening(self):
        if self.server_socket:
            self.server_socket.close()
        self.listening = False
        print("Stopped listening.")

    def listen_for_connection(self):
        try:
            while self.listening:
                try:
                    self.server_socket.settimeout(1)

                    client, addr = self.server_socket.accept()
                    self.last_client_ip = addr[0]

                    gc.collect()

                    receiving_start_time = time.perf_counter()
                    data = client.recv(16384).decode()
                    receiving_end_time = time.perf_counter()

                    msg = json.loads(data)
                    if msg.get('is_quantum_state'):
                        self.protocol_start_time = receiving_start_time
                        self.state_receiving_time = (receiving_end_time - receiving_start_time) * 1_000_000
                        client.sendall(json.dumps({'received': True}).encode())

                    if 'sender_bases' in msg and self.bob_bases and self.bob_measurements:
                        sb = msg['sender_bases']

                        gc.collect()
                        basis_start_time = time.perf_counter()
                        kept_indices = [i for i, b in enumerate(sb) if b == self.bob_bases[i]]
                        basis_end_time = time.perf_counter()
                        self.basis_comparison_time = (basis_end_time - basis_start_time) * 1_000_000  

                        if self.basis_comparison_time > 0:
                            self.key_throughput = (len(kept_indices) / self.basis_comparison_time)

                        final_key_gen_start = time.perf_counter()
                        final_key = ''.join(str(self.bob_measurements[i]) for i in kept_indices)
                        self.final_key = final_key
                        final_key_gen_end = time.perf_counter()

                        self.state_measuring_time += (final_key_gen_end - final_key_gen_start) * 1_000_000
                        
                        client.sendall(json.dumps({
                            'bob_bases': self.bob_bases,
                            'bob_measurements': self.bob_measurements
                        }).encode())

                        protocol_end_time = time.perf_counter()
                        if self.protocol_start_time is not None:
                            self.total_protocol_time = (protocol_end_time - self.protocol_start_time) * 1_000_000  

                        self.display_results(None, sb, self.bob_bases, self.bob_measurements, kept_indices)
                        client.close()
                        self.client_socket = None
                        self.stop_listening()
                        break
                        continue

                    self.client_socket = client
                    self.received_data = msg
                    print("Quantum state received. Automatically measuring...")
                    self.measure_quantum_state()

                except socket.timeout:
                    continue
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

            print(f"\nBob's Bases: {''.join(bb)}")
            print(f"Bob's Measurements: {''.join(str(m) for m in measurements)}")

            measure_end_time = time.perf_counter()
            self.state_measuring_time = (measure_end_time - measure_start_time) * 1_000_000

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

    def display_results(self, sender_bits, sender_bases, bob_bases, bob_measurements, kept_indices=None):
        show_alice = sender_bits is not None
        gc.collect()
        if kept_indices is None and sender_bases:
            if self.basis_comparison_time == 0:
                basis_start_time = time.perf_counter()
                kept_indices = [i for i, b in enumerate(sender_bases) if b == bob_bases[i]]
                basis_end_time = time.perf_counter()
                self.basis_comparison_time = (basis_end_time - basis_start_time) * 1_000_000

                if self.basis_comparison_time > 0 and kept_indices:
                    self.key_throughput = (len(kept_indices) / self.basis_comparison_time)
            else:
                kept_indices = [i for i, b in enumerate(sender_bases) if b == bob_bases[i]]

        print("\nBB84 Protocol Results")
        print("-" * 60)
        if show_alice:
            print("No.\tA.Bit\tA.Base\tB.Base\tB.Measure\tKept?")
        else:
            print("No.\tA.Base\tB.Base\tB.Measure\tKept?")

        for i in range(len(sender_bases)):
            kept = "Yes" if i in kept_indices else "No"
            if show_alice:
                print(f"{i}\t{sender_bits[i]}\t{sender_bases[i]}\t{bob_bases[i]}\t{bob_measurements[i]}\t{kept}")
            else:
                print(f"{i}\t{sender_bases[i]}\t{bob_bases[i]}\t{bob_measurements[i]}\t{kept}")

        final = ''.join(str(bob_measurements[i]) for i in kept_indices)
        self.final_key = final
        print("-" * 60)
        print(f"Final Shared key: {final}")

        total = len(sender_bases)
        match = len(kept_indices)
        rate = (match / total * 100) if total else 0
        print(f"\nTotal qubits: {total}")
        print(f"Matching Bases: {match}")
        print(f"Key Generation Rate: {rate:.2f}%")

        print("\n======= RECEIVER BENCHMARKS =======")
        print(f"Quantum State Receiving Time: {self.state_receiving_time:.2f} microseconds")
        print(f"Quantum State Measurement Time: {self.state_measuring_time:.2f} microseconds")
        print(f"Basis Comparison Time: {self.basis_comparison_time:.2f} microseconds")
        print(f"Key Generation Throughput: {self.key_throughput:.2f} bits/microsecond")
        print(f"Total Protocol Time: {self.total_protocol_time:.2f} microseconds")

if __name__ == "__main__":
    receiver = BB84Receiver()
    print("BB84 Quantum Key Distribution - Receiver (Bob)")
    print("==============================================")

    port = 12345
    receiver.start_listening(port)

    try:
        while receiver.listening:
            pass
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        receiver.stop_listening()