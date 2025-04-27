import socket
import base64
import threading
import sys
import time
from datetime import datetime
import argparse
from Crypto.Cipher import AES
import hashlib
import hmac
from argon2.low_level import hash_secret_raw, Type
from kyber_wrapper768 import generate_keypair, decapsulate
import numpy as np

class QuantumSecureReceiver:
    def __init__(self, port=5000, iterations=100, warmups=20):
        self.hybrid_key = "a7e3f8c2d15b94e6d0c7a5b9e8f1c2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5"
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.symmetric_key = None
        self.final_session_key = None
        self.iterations = iterations
        self.warmups = warmups

        self.connection_times = []
        self.auth_times = []
        self.key_exchange_times = []
        self.final_key_derivation_times = []
        self.total_times = []

        self.connection_start_time = 0
        self.connection_end_time = 0
        self.auth_start_time = 0
        self.auth_end_time = 0
        self.key_exchange_start_time = 0
        self.key_exchange_end_time = 0
        self.final_key_derivation_start_time = 0
        self.final_key_derivation_end_time = 0

    def log(self, message):
        timestamp = datetime.now().strftime("%I:%M:%S %p")
        print(f"[{timestamp}] {message}")

    def get_local_ip(self):
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except Exception:
            return "127.0.0.1" 

    def generate_key_from_hybrid_key(self, hybrid_key):
        try:
            if len(hybrid_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in hybrid_key):
                key = bytes.fromhex(hybrid_key)
                return key
            else:
                full_digest = hashlib.sha3_512(hybrid_key.encode()).digest()
                return full_digest
        except Exception:
            full_digest = hashlib.sha3_512(hybrid_key.encode()).digest()
            return full_digest

    def start_server(self):
        ip = self.get_local_ip()

        self.symmetric_key = self.generate_key_from_hybrid_key(self.hybrid_key)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(1)
        
        self.log(f"Server started. Listening on {ip}:{self.port}")
        self.log(f"Using hybrid key: {self.hybrid_key}")
        self.log(f"Running {self.warmups} warmup iterations followed by {self.iterations} benchmark iterations...")

        self.client_socket, self.client_address = self.server_socket.accept()
        self.log(f"Initial connection established with {self.client_address[0]}:{self.client_address[1]}")

        self.client_socket.sendall("READY_TO_BEGIN".encode('utf-8'))

        self.log("Starting warmup iterations...")
        for i in range(self.warmups):
            self.client_socket.sendall(f"START_WARMUP:{i+1}".encode('utf-8'))

            if i > 0:
                self.client_socket.close()

            self.client_socket, self.client_address = self.server_socket.accept()

            self.run_single_iteration(is_warmup=True)

            ready_msg = self.client_socket.recv(1024).decode('utf-8')
            if ready_msg != "READY_FOR_NEXT":
                self.log(f"Client not ready for next warmup iteration. Aborting. Received: {ready_msg}")
                break
            
            if (i+1) % 5 == 0:
                self.log(f"Warmup progress: {i+1}/{self.warmups}")
                
        self.log("Warmup iterations completed")

        self.client_socket.sendall("START_BENCHMARK".encode('utf-8'))
        ready_msg = self.client_socket.recv(1024).decode('utf-8')
        if ready_msg != "READY_FOR_BENCHMARK":
            self.log(f"Client not ready for benchmark. Aborting. Received: {ready_msg}")
            return
            
        progress_counter = 0 

        for i in range(self.iterations):
            self.client_socket.sendall(f"START_ITERATION:{i+1}".encode('utf-8'))

            if i > 0:
                self.client_socket.close()

            self.connection_start_time = time.perf_counter()
            self.client_socket, self.client_address = self.server_socket.accept()
            self.connection_end_time = time.perf_counter()

            success = self.run_single_iteration()
            
            if success:
                connection_time = (self.connection_end_time - self.connection_start_time) * 1000000 
                auth_time = (self.auth_end_time - self.auth_start_time) * 1000000  
                key_exchange_time = (self.key_exchange_end_time - self.key_exchange_start_time) * 1000000  
                final_key_time = (self.final_key_derivation_end_time - self.final_key_derivation_start_time) * 1000000 
                total_time = connection_time + auth_time + key_exchange_time + final_key_time
                
                self.connection_times.append(connection_time)
                self.auth_times.append(auth_time)
                self.key_exchange_times.append(key_exchange_time)
                self.final_key_derivation_times.append(final_key_time)
                self.total_times.append(total_time)

            ready_msg = self.client_socket.recv(1024).decode('utf-8')
            if ready_msg != "READY_FOR_NEXT":
                self.log(f"Client not ready for next iteration. Aborting. Received: {ready_msg}")
                break
            
            progress_counter += 1
            if progress_counter % 10 == 0 or progress_counter == self.iterations:
                self.log(f"Authentication completed: ({progress_counter}/{self.iterations})")

        self.client_socket.sendall("BENCHMARK_COMPLETE".encode('utf-8'))

        self.print_benchmark_results()

        self.client_socket.close()
        self.server_socket.close()
    
    def run_single_iteration(self, is_warmup=False):
        try:
            received_key = self.client_socket.recv(2048).decode('utf-8')
            if received_key != self.hybrid_key:
                self.log("⚠️ Hybrid key mismatch! Aborting connection.")
                return False

            if not self.mutual_authenticate_server(is_warmup):
                return False

            if not self.perform_ephemeral_key_exchange(is_warmup):
                return False
                
            return True
            
        except Exception as e:
            self.log(f"Error in iteration: {str(e)}")
            return False

    def mutual_authenticate_server(self, is_warmup=False):
        try:
            if not is_warmup:
                self.auth_start_time = time.perf_counter()

            server_timestamp = int(time.time())
            self.client_socket.sendall(("SERVER_TIMESTAMP:" + str(server_timestamp)).encode('utf-8'))

            client_response = self.client_socket.recv(2048).decode('utf-8')
            if not client_response.startswith("CLIENT_RESPONSE:"):
                self.log("Authentication Error: Invalid response from client")
                return False
                
            client_hmac = client_response[len("CLIENT_RESPONSE:"):]
            expected_hmac = hmac.new(self.symmetric_key, str(server_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            
            if client_hmac != expected_hmac:
                self.log("Authentication Error: Client authentication failed")
                return False

            client_timestamp_msg = self.client_socket.recv(2048).decode('utf-8')
            if not client_timestamp_msg.startswith("CLIENT_TIMESTAMP:"):
                self.log("Authentication Error: Invalid client timestamp challenge")
                return False
                
            client_timestamp_str = client_timestamp_msg[len("CLIENT_TIMESTAMP:"):]
            try:
                client_timestamp = int(client_timestamp_str)
            except:
                self.log("Authentication Error: Invalid client timestamp format")
                return False

            if abs(int(time.time()) - client_timestamp) > 120:
                self.log("Authentication Error: Client timestamp is not fresh")
                return False

            server_response = hmac.new(self.symmetric_key, str(client_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            self.client_socket.sendall(("SERVER_RESPONSE:" + server_response).encode('utf-8'))
            
            if not is_warmup:
                self.auth_end_time = time.perf_counter()
            return True
            
        except Exception as e:
            self.log(f"Authentication Error: {str(e)}")
            return False

    def perform_ephemeral_key_exchange(self, is_warmup=False):
        try:
            if not is_warmup:
                self.key_exchange_start_time = time.perf_counter()

            public_key, secret_key = generate_keypair()
            public_key_b64 = base64.b64encode(public_key).decode('utf-8')

            msg = "KYBER_EPHEMERAL:" + public_key_b64 + "\n"
            self.client_socket.sendall(msg.encode('utf-8'))

            ciphertext_msg = self.client_socket.recv(4096).decode('utf-8').strip()
            if not ciphertext_msg.startswith("KYBER_CIPHERTEXT:"):
                self.log("Ephemeral Key Exchange Error: Invalid Kyber ciphertext message")
                return False

            ciphertext_b64 = ciphertext_msg[len("KYBER_CIPHERTEXT:"):]
            ciphertext = base64.b64decode(ciphertext_b64)

            shared_secret = decapsulate(ciphertext, secret_key)
            
            if not is_warmup:
                self.key_exchange_end_time = time.perf_counter()

            if not is_warmup:
                self.final_key_derivation_start_time = time.perf_counter()
            
            self.final_session_key = hash_secret_raw(
                secret=shared_secret,                
                salt=self.symmetric_key,              
                time_cost=4,                         
                memory_cost=102400,                   
                parallelism=8,                        
                hash_len=32,                       
                type=Type.ID                         
            )
            
            if not is_warmup:
                self.final_key_derivation_end_time = time.perf_counter()

            self.client_socket.sendall("KEY_EXCHANGE_COMPLETE".encode('utf-8'))
            return True
            
        except Exception as e:
            self.log(f"Ephemeral Key Exchange Error: {str(e)}")
            return False

    def print_benchmark_results(self):
        self.log("\n========== AVERAGE BENCHMARK RESULTS (µs / ms) ==========")
        self.log(f"1. Connection time: avg={np.mean(self.connection_times):.2f}µs / {(np.mean(self.connection_times)/1000):.4f}ms")
        self.log(f"2. Authentication time: avg={np.mean(self.auth_times):.2f}µs / {(np.mean(self.auth_times)/1000):.4f}ms")
        self.log(f"3. Key exchange time: avg={np.mean(self.key_exchange_times):.2f}µs / {(np.mean(self.key_exchange_times)/1000):.4f}ms")
        self.log(f"4. Final key derivation time: avg={np.mean(self.final_key_derivation_times):.2f}µs / {(np.mean(self.final_key_derivation_times)/1000):.4f}ms")
        self.log(f"5. Total time: avg={np.mean(self.total_times):.2f}µs / {(np.mean(self.total_times)/1000):.4f}ms")
        self.log("=========================================================")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quantum Secure Receiver')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('-i', '--iterations', type=int, default=100, help='Number of iterations for benchmark')
    parser.add_argument('-w', '--warmups', type=int, default=20, help='Number of warmup iterations')
    args = parser.parse_args()
    
    receiver = QuantumSecureReceiver(port=args.port, iterations=args.iterations, warmups=args.warmups)
    receiver.start_server()