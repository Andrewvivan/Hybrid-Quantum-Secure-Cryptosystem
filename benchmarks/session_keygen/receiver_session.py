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

class QuantumSecureReceiver:
    def __init__(self, port=5000):
        self.hybrid_key = "a7e3f8c2d15b94e6d0c7a5b9e8f1c2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5"
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.symmetric_key = None
        self.final_session_key = None

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
        try:
            ip = self.get_local_ip()
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(1)
            
            self.log(f"Server started. Listening on {ip}:{self.port}")
            self.log(f"Using hybrid key: {self.hybrid_key}")

            self.symmetric_key = self.generate_key_from_hybrid_key(self.hybrid_key)

            self.connection_start_time = time.perf_counter()
            self.client_socket, self.client_address = self.server_socket.accept()
            self.connection_end_time = time.perf_counter()
            
            self.log(f"Connected to {self.client_address[0]}:{self.client_address[1]}")

            received_key = self.client_socket.recv(2048).decode('utf-8')
            if received_key != self.hybrid_key:
                self.log("⚠️ Hybrid key mismatch! Aborting connection.")
                self.client_socket.close()
                return False
            
            self.log("✅ Hybrid key verified")

            if not self.mutual_authenticate_server():
                return False

            if not self.perform_ephemeral_key_exchange():
                return False

            self.print_benchmarks()

            self.log("Benchmark complete. Closing connection in 5 seconds...")
            time.sleep(5)
            self.client_socket.close()
            self.server_socket.close()
            
            return True
            
        except Exception as e:
            self.log(f"Server Error: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
            if self.server_socket:
                self.server_socket.close()
            return False

    def mutual_authenticate_server(self):
        try:
            self.log("Starting mutual authentication...")
            self.auth_start_time = time.perf_counter()

            server_timestamp = int(time.time())
            self.client_socket.sendall(("SERVER_TIMESTAMP:" + str(server_timestamp)).encode('utf-8'))

            client_response = self.client_socket.recv(2048).decode('utf-8')
            if not client_response.startswith("CLIENT_RESPONSE:"):
                self.log("Authentication Error: Invalid response from client")
                self.client_socket.close()
                return False
                
            client_hmac = client_response[len("CLIENT_RESPONSE:"):]
            expected_hmac = hmac.new(self.symmetric_key, str(server_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            
            if client_hmac != expected_hmac:
                self.log("Authentication Error: Client authentication failed")
                self.client_socket.close()
                return False

            client_timestamp_msg = self.client_socket.recv(2048).decode('utf-8')
            if not client_timestamp_msg.startswith("CLIENT_TIMESTAMP:"):
                self.log("Authentication Error: Invalid client timestamp challenge")
                self.client_socket.close()
                return False
                
            client_timestamp_str = client_timestamp_msg[len("CLIENT_TIMESTAMP:"):]
            try:
                client_timestamp = int(client_timestamp_str)
            except:
                self.log("Authentication Error: Invalid client timestamp format")
                self.client_socket.close()
                return False

            if abs(int(time.time()) - client_timestamp) > 120:
                self.log("Authentication Error: Client timestamp is not fresh")
                self.client_socket.close()
                return False

            server_response = hmac.new(self.symmetric_key, str(client_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            self.client_socket.sendall(("SERVER_RESPONSE:" + server_response).encode('utf-8'))
            
            self.auth_end_time = time.perf_counter()
            auth_duration = (self.auth_end_time - self.auth_start_time) * 1000000
            self.log(f"✅ Authentication successful in {auth_duration:.2f}µs")
            return True
            
        except Exception as e:
            self.log(f"Authentication Error: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
            return False

    def perform_ephemeral_key_exchange(self):
        try:
            self.log("Starting ephemeral key exchange using Kyber768...")
            self.key_exchange_start_time = time.perf_counter()

            public_key, secret_key = generate_keypair()
            public_key_b64 = base64.b64encode(public_key).decode('utf-8')

            msg = "KYBER_EPHEMERAL:" + public_key_b64 + "\n"
            self.client_socket.sendall(msg.encode('utf-8'))

            ciphertext_msg = self.client_socket.recv(4096).decode('utf-8').strip()
            if not ciphertext_msg.startswith("KYBER_CIPHERTEXT:"):
                self.log("Ephemeral Key Exchange Error: Invalid Kyber ciphertext message")
                self.client_socket.close()
                return False

            ciphertext_b64 = ciphertext_msg[len("KYBER_CIPHERTEXT:"):]
            ciphertext = base64.b64decode(ciphertext_b64)

            shared_secret = decapsulate(ciphertext, secret_key)
            
            self.key_exchange_end_time = time.perf_counter()
            key_exchange_duration = (self.key_exchange_end_time - self.key_exchange_start_time) * 1000000
            self.log(f"✅ Ephemeral key exchange successful in {key_exchange_duration:.2f}µs")

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
            
            key_derivation_duration = (self.final_key_derivation_end_time - self.final_key_derivation_start_time) * 1000000
            self.log(f"✅ Final session key derived in {key_derivation_duration:.2f}µs")

            self.client_socket.sendall("KEY_EXCHANGE_COMPLETE".encode('utf-8'))
            return True
            
        except Exception as e:
            self.log(f"Ephemeral Key Exchange Error: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
            return False

    def print_benchmarks(self):
        self.log("\n========== BENCHMARK RESULTS ==========")
        self.log(f"1. Connection establishment time: {(self.connection_end_time - self.connection_start_time) * 1000000:.2f}µs")
        self.log(f"2. Total authentication time: {(self.auth_end_time - self.auth_start_time) * 1000000:.2f}µs")
        self.log(f"3. Ephemeral key exchange time: {(self.key_exchange_end_time - self.key_exchange_start_time) * 1000000:.2f}µs")
        self.log(f"4. Final session key derivation time: {(self.final_key_derivation_end_time - self.final_key_derivation_start_time) * 1000000:.2f}µs")
        total_time = (self.final_key_derivation_end_time - self.connection_start_time) * 1000000
        self.log(f"5. Total time (connection to final key): {total_time:.2f}µs")
        self.log("=======================================")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quantum Secure Receiver')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port to listen on')
    args = parser.parse_args()
    
    receiver = QuantumSecureReceiver(port=args.port)
    receiver.start_server()