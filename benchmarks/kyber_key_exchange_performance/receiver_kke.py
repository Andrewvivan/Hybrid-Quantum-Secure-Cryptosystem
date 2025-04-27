import socket
import json
import threading
import time
from kyber_wrapper1024 import encapsulate

class KyberReceiverBenchmark:
    def __init__(self):
        self.sender_public_key = None
        self.encapsulated_key = None
        self.shared_secret = None
        self.server_socket = None
        self.listening = False
        self.total_encapsulation_time = 0
        self.total_key_establishment_time = 0
        self.iterations = 0
        self.max_iterations = 10000
        self.is_warmup = True
        self.warmup_iterations = 1000

    def get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"Error getting IP address: {e}")
            return "127.0.0.1"  

    def process_public_key(self, public_key_hex):
        self.sender_public_key = bytes.fromhex(public_key_hex)
        
        start_time = time.time()
        self.encapsulated_key, self.shared_secret = encapsulate(self.sender_public_key)
        end_time = time.time()
        
        encapsulation_time = (end_time - start_time) * 1_000_000  
        return encapsulation_time

    def handle_connection(self):
        try:
            total_iterations = self.warmup_iterations + self.max_iterations
            current_iteration = 0
            
            print(f"\nStarting warmup phase ({self.warmup_iterations} iterations)...")
            
            while self.listening and current_iteration < total_iterations:
                if current_iteration == self.warmup_iterations:
                    self.total_encapsulation_time = 0
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
                
                client_socket, addr = self.server_socket.accept()

                data = client_socket.recv(16384).decode()
                received_data = json.loads(data)
                
                if 'public_key' in received_data:
                    encapsulation_time = self.process_public_key(received_data['public_key'])

                    data = {
                        'encapsulated_key': self.encapsulated_key.hex()
                    }
                    client_socket.sendall(json.dumps(data).encode())

                    response = json.loads(client_socket.recv(1024).decode())
                    
                    if response.get('status') == 'success':
                        establishment_time = (time.time() - establishment_start_time) * 1_000_000  

                        if not self.is_warmup:
                            self.total_encapsulation_time += encapsulation_time
                            self.total_key_establishment_time += establishment_time
                            self.iterations += 1
                        
                        current_iteration += 1
                else:
                    print("Error: No public key received from sender")
                
                client_socket.close()
                
                if not self.is_warmup and self.iterations >= self.max_iterations:
                    self.print_final_results()
                    self.stop_listening()
                
        except Exception as e:
            print(f"Error in connection handler: {e}")

    def print_final_results(self):
        if self.iterations > 0:
            avg_encapsulation = self.total_encapsulation_time / self.iterations
            avg_establishment = self.total_key_establishment_time / self.iterations
            
            print("\n===== BENCHMARK RESULTS =====")
            print(f"Completed {self.iterations} iterations (after {self.warmup_iterations} warmup iterations)")
            print(f"Average encapsulation time: {avg_encapsulation:.2f} μs")
            print(f"Average key establishment time: {avg_establishment:.2f} μs")
            print("=============================")
    
    def start_listening(self, host="0.0.0.0", port=12345):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen()
            
            self.listening = True
            ip = self.get_ip()
            print(f"Receiver listening on {ip}:{port}")
            print("Waiting for sender to connect...")

            threading.Thread(target=self.handle_connection, daemon=True).start()
            
        except Exception as e:
            print(f"Error starting server: {e}")
    
    def stop_listening(self):
        if self.server_socket:
            self.listening = False
            self.server_socket.close()
            print("Server stopped.")

def main():
    print("Kyber Key Exchange Benchmark - Receiver")
    print("======================================")
    
    receiver = KyberReceiverBenchmark()
    receiver.start_listening()
    
    try:
        total_iterations = receiver.warmup_iterations + receiver.max_iterations
        current_iteration = 0
        
        while receiver.listening and current_iteration < total_iterations:
            time.sleep(1)
            current_iteration = receiver.iterations
            if not receiver.is_warmup:
                current_iteration += receiver.warmup_iterations
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user.")
        receiver.print_final_results()
        receiver.stop_listening()

if __name__ == "__main__":
    main()