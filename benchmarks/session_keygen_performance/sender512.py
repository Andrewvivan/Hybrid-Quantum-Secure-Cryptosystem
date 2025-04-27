import socket
import base64
import sys
import time
from datetime import datetime
import argparse
from Crypto.Cipher import AES
import hashlib
import hmac
from argon2.low_level import hash_secret_raw, Type
from kyber_wrapper512 import encapsulate
import numpy as np

class QuantumSecureSender:
    def __init__(self, receiver_ip, port=5000, iterations=100):
        self.hybrid_key = "a7e3f8c2d15b94e6d0c7a5b9e8f1c2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5"
        self.receiver_ip = receiver_ip
        self.port = port
        self.socket = None
        self.symmetric_key = None
        self.final_session_key = None
        self.iterations = iterations

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

    def connect_to_receiver(self):
        self.log(f"Connecting to receiver at {self.receiver_ip}:{self.port}")
        self.log(f"Using hybrid key: {self.hybrid_key}")
        self.log(f"Running {self.iterations} benchmark iterations...")

        self.symmetric_key = self.generate_key_from_hybrid_key(self.hybrid_key)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.receiver_ip, self.port))

        ready_msg = self.socket.recv(1024).decode('utf-8')
        if ready_msg != "READY_TO_BEGIN":
            self.log(f"Server not ready to begin benchmark: {ready_msg}")
            self.socket.close()
            return
            
        progress_counter = 0
        
        for i in range(self.iterations):
            start_msg = self.socket.recv(1024).decode('utf-8')
            if not start_msg.startswith("START_ITERATION:"):
                self.log(f"Unexpected message from server: {start_msg}")
                break

            if i > 0:
                self.socket.close()

            self.connection_start_time = time.perf_counter()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.receiver_ip, self.port))
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

            self.socket.sendall("READY_FOR_NEXT".encode('utf-8'))
            
            progress_counter += 1
            if progress_counter % 10 == 0 or progress_counter == self.iterations:
                self.log(f"Authentication completed: ({progress_counter}/{self.iterations})")

        completion_msg = self.socket.recv(1024).decode('utf-8')
        if completion_msg == "BENCHMARK_COMPLETE":
            self.log("Benchmark completed successfully")

        self.print_benchmark_results()

        self.socket.close()
    
    def run_single_iteration(self):
        try:
            self.socket.send(self.hybrid_key.encode('utf-8'))

            if not self.mutual_authenticate_client():
                return False

            if not self.perform_ephemeral_key_exchange():
                return False
                
            return True
            
        except Exception as e:
            self.log(f"Error in iteration: {str(e)}")
            return False

    def mutual_authenticate_client(self):
        try:
            self.auth_start_time = time.perf_counter()

            server_timestamp_msg = self.socket.recv(2048).decode('utf-8')
            if not server_timestamp_msg.startswith("SERVER_TIMESTAMP:"):
                self.log("Authentication Error: Invalid timestamp challenge from server")
                return False
                
            server_timestamp_str = server_timestamp_msg[len("SERVER_TIMESTAMP:"):]
            try:
                server_timestamp = int(server_timestamp_str)
            except:
                self.log("Authentication Error: Invalid server timestamp format")
                return False

            if abs(int(time.time()) - server_timestamp) > 120:
                self.log("Authentication Error: Server timestamp is not fresh")
                return False

            client_response = hmac.new(self.symmetric_key, str(server_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            self.socket.sendall(("CLIENT_RESPONSE:" + client_response).encode('utf-8'))

            client_timestamp = int(time.time())
            self.socket.sendall(("CLIENT_TIMESTAMP:" + str(client_timestamp)).encode('utf-8'))

            server_response_msg = self.socket.recv(2048).decode('utf-8')
            if not server_response_msg.startswith("SERVER_RESPONSE:"):
                self.log("Authentication Error: Invalid server response for timestamp challenge")
                return False
                
            server_response = server_response_msg[len("SERVER_RESPONSE:"):]
            expected_response = hmac.new(self.symmetric_key, str(client_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            
            if server_response != expected_response:
                self.log("Authentication Error: Server authentication failed")
                return False
                
            self.auth_end_time = time.perf_counter()
            return True
            
        except Exception as e:
            self.log(f"Authentication Error: {str(e)}")
            return False

    def perform_ephemeral_key_exchange(self):
        try:
            self.key_exchange_start_time = time.perf_counter()

            msg = self.socket.recv(4096).decode('utf-8').strip()
            if not msg.startswith("KYBER_EPHEMERAL:"):
                self.log("Ephemeral Key Exchange Error: Invalid Kyber public key message from server")
                return False

            public_key_b64 = msg[len("KYBER_EPHEMERAL:"):]
            public_key = base64.b64decode(public_key_b64)

            ciphertext, shared_secret = encapsulate(public_key)
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

            response_msg = "KYBER_CIPHERTEXT:" + ciphertext_b64 + "\n"
            self.socket.sendall(response_msg.encode('utf-8'))
            
            self.key_exchange_end_time = time.perf_counter()

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
            self.final_key_derivation_end_time = time.perf_counter()

            confirmation = self.socket.recv(2048).decode('utf-8')
            if confirmation != "KEY_EXCHANGE_COMPLETE":
                self.log(f"Unexpected confirmation message: {confirmation}")
            
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
    parser = argparse.ArgumentParser(description='Quantum Secure Sender')
    parser.add_argument('receiver_ip', nargs='?', default='127.0.0.1', help='IP address of the receiver (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port of the receiver')
    parser.add_argument('-i', '--iterations', type=int, default=100, help='Number of iterations for benchmark')
    args = parser.parse_args()
    
    sender = QuantumSecureSender(receiver_ip=args.receiver_ip, port=args.port, iterations=args.iterations)
    sender.connect_to_receiver()