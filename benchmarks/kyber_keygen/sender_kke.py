import socket
import json
import time
import sys
from kyber_wrapper1024 import generate_keypair, decapsulate

class KyberSenderBenchmark:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.shared_secret = None
        self.total_keygen_time = 0
        self.total_decapsulation_time = 0
        self.total_key_establishment_time = 0
        self.iterations = 0
        self.max_iterations = 10000
        self.is_warmup = True
        self.warmup_iterations = 1000

    def generate_kyber_keys(self):
        start_time = time.time()
        self.public_key, self.private_key = generate_keypair()
        end_time = time.time()
        return (end_time - start_time) * 1_000_000

    def perform_decapsulation(self, encapsulated_key_hex):
        encapsulated_key_bytes = bytes.fromhex(encapsulated_key_hex)
        
        start_time = time.time()
        self.shared_secret = decapsulate(encapsulated_key_bytes, self.private_key)
        end_time = time.time()
        
        return (end_time - start_time) * 1_000_000  

    def run_benchmark(self, receiver_ip, port=12345):
        print(f"Starting benchmark with receiver at {receiver_ip}:{port}")
        print(f"Warmup iterations: {self.warmup_iterations}")
        print(f"Benchmark iterations: {self.max_iterations}")
        
        total_iterations = self.warmup_iterations + self.max_iterations
        current_iteration = 0

        print("\nStarting warmup phase...")
        
        while current_iteration < total_iterations:
            try:
                if current_iteration == self.warmup_iterations:
                    self.total_keygen_time = 0
                    self.total_decapsulation_time = 0
                    self.total_key_establishment_time = 0
                    self.iterations = 0
                    self.is_warmup = False
                    print(f"\nWarmup complete. Starting benchmark ({self.max_iterations} iterations)...")

                phase = "Warmup" if self.is_warmup else "Benchmark"
                max_iter = self.warmup_iterations if self.is_warmup else self.max_iterations
                progress_iter = current_iteration if self.is_warmup else current_iteration - self.warmup_iterations
                
                if progress_iter % 10 == 0 or progress_iter == max_iter-1:
                    print(f"{phase} progress: ({progress_iter+1}/{max_iter})")

                establishment_start_time = time.time()

                keygen_time = self.generate_kyber_keys()

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((receiver_ip, port))

                    data = {
                        'public_key': self.public_key.hex()
                    }
                    s.sendall(json.dumps(data).encode())

                    data = s.recv(16384).decode()
                    received_data = json.loads(data)
                    
                    if 'encapsulated_key' in received_data:
                        decapsulation_time = self.perform_decapsulation(received_data['encapsulated_key'])

                        response = {'status': 'success', 'shared_secret_hash': hash(self.shared_secret)}
                        s.sendall(json.dumps(response).encode())

                        establishment_time = (time.time() - establishment_start_time) * 1_000_000  

                        if not self.is_warmup:
                            self.total_keygen_time += keygen_time
                            self.total_decapsulation_time += decapsulation_time
                            self.total_key_establishment_time += establishment_time
                            self.iterations += 1
                        
                        current_iteration += 1
                    else:
                        print("Error: No encapsulated key received from receiver")
                        
            except Exception as e:
                print(f"Error in iteration {current_iteration+1}: {e}")
                time.sleep(1)
        
        self.print_final_results()

    def print_final_results(self):
        if self.iterations > 0:
            avg_keygen = self.total_keygen_time / self.iterations
            avg_decapsulation = self.total_decapsulation_time / self.iterations
            avg_establishment = self.total_key_establishment_time / self.iterations
            
            print("\n===== BENCHMARK RESULTS =====")
            print(f"Completed {self.iterations} iterations (after {self.warmup_iterations} warmup iterations)")
            print(f"Average key generation time: {avg_keygen:.2f} μs")
            print(f"Average decapsulation time: {avg_decapsulation:.2f} μs")
            print(f"Average key establishment time: {avg_establishment:.2f} μs")
            print("=============================")

def main():
    print("Kyber Key Exchange Benchmark - Sender")
    print("====================================")
    
    if len(sys.argv) < 2:
        print("Usage: python sender.py <receiver_ip>")
        sys.exit(1)
    
    receiver_ip = sys.argv[1]
    port = 12345
    
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Port must be a number")
            sys.exit(1)
    
    sender = KyberSenderBenchmark()
    sender.run_benchmark(receiver_ip, port)

if __name__ == "__main__":
    main()