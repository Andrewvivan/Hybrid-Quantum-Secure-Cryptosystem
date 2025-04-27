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
from kyber_wrapper768 import encapsulate

class QuantumSecureSender:
    def __init__(self, receiver_ip, port=5000):
        self.hybrid_key = "a7e3f8c2d15b94e6d0c7a5b9e8f1c2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5a6b7c8d9a0b1c2d3e4f5"
        self.receiver_ip = receiver_ip
        self.port = port
        self.socket = None
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
        try:
            self.log(f"Connecting to receiver at {self.receiver_ip}:{self.port}")
            self.log(f"Using hybrid key: {self.hybrid_key}")

            self.symmetric_key = self.generate_key_from_hybrid_key(self.hybrid_key)

            self.connection_start_time = time.perf_counter()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.receiver_ip, self.port))
            self.connection_end_time = time.perf_counter()
            
            connection_duration = (self.connection_end_time - self.connection_start_time) * 1000000
            self.log(f"Connected in {connection_duration:.2f}µs")

            self.socket.send(self.hybrid_key.encode('utf-8'))

            if not self.mutual_authenticate_client():
                return False

            if not self.perform_ephemeral_key_exchange():
                return False

            self.print_benchmarks()

            self.log("Benchmark complete. Closing connection in 5 seconds...")
            time.sleep(5)
            self.socket.close()
            
            return True
            
        except Exception as e:
            self.log(f"Connection Error: {str(e)}")
            if self.socket:
                self.socket.close()
            return False

    def mutual_authenticate_client(self):
        try:
            self.log("Starting mutual authentication...")
            self.auth_start_time = time.perf_counter()

            server_timestamp_msg = self.socket.recv(2048).decode('utf-8')
            if not server_timestamp_msg.startswith("SERVER_TIMESTAMP:"):
                self.log("Authentication Error: Invalid timestamp challenge from server")
                self.socket.close()
                return False
                
            server_timestamp_str = server_timestamp_msg[len("SERVER_TIMESTAMP:"):]
            try:
                server_timestamp = int(server_timestamp_str)
            except:
                self.log("Authentication Error: Invalid server timestamp format")
                self.socket.close()
                return False

            if abs(int(time.time()) - server_timestamp) > 120:
                self.log("Authentication Error: Server timestamp is not fresh")
                self.socket.close()
                return False

            client_response = hmac.new(self.symmetric_key, str(server_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            self.socket.sendall(("CLIENT_RESPONSE:" + client_response).encode('utf-8'))

            client_timestamp = int(time.time())
            self.socket.sendall(("CLIENT_TIMESTAMP:" + str(client_timestamp)).encode('utf-8'))

            server_response_msg = self.socket.recv(2048).decode('utf-8')
            if not server_response_msg.startswith("SERVER_RESPONSE:"):
                self.log("Authentication Error: Invalid server response for timestamp challenge")
                self.socket.close()
                return False
                
            server_response = server_response_msg[len("SERVER_RESPONSE:"):]
            expected_response = hmac.new(self.symmetric_key, str(client_timestamp).encode('utf-8'), hashlib.sha256).hexdigest()
            
            if server_response != expected_response:
                self.log("Authentication Error: Server authentication failed")
                self.socket.close()
                return False
                
            self.auth_end_time = time.perf_counter()
            auth_duration = (self.auth_end_time - self.auth_start_time) * 1000000
            self.log(f"✅ Authentication successful in {auth_duration:.2f}µs")
            return True
            
        except Exception as e:
            self.log(f"Authentication Error: {str(e)}")
            if self.socket:
                self.socket.close()
            return False

    def perform_ephemeral_key_exchange(self):
        try:
            self.log("Starting ephemeral key exchange using Kyber768...")
            self.key_exchange_start_time = time.perf_counter()

            msg = self.socket.recv(4096).decode('utf-8').strip()
            if not msg.startswith("KYBER_EPHEMERAL:"):
                self.log("Ephemeral Key Exchange Error: Invalid Kyber public key message from server")
                self.socket.close()
                return False

            public_key_b64 = msg[len("KYBER_EPHEMERAL:"):]
            public_key = base64.b64decode(public_key_b64)

            ciphertext, shared_secret = encapsulate(public_key)
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

            response_msg = "KYBER_CIPHERTEXT:" + ciphertext_b64 + "\n"
            self.socket.sendall(response_msg.encode('utf-8'))
            
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

            confirmation = self.socket.recv(2048).decode('utf-8')
            if confirmation == "KEY_EXCHANGE_COMPLETE":
                self.log("Key exchange confirmed by server")
            
            return True
            
        except Exception as e:
            self.log(f"Ephemeral Key Exchange Error: {str(e)}")
            if self.socket:
                self.socket.close()
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
    parser = argparse.ArgumentParser(description='Quantum Secure Sender')
    parser.add_argument('receiver_ip', help='IP address of the receiver')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port of the receiver')
    args = parser.parse_args()
    
    sender = QuantumSecureSender(receiver_ip=args.receiver_ip, port=args.port)
    sender.connect_to_receiver()