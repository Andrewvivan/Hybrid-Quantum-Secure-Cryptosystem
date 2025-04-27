import socket
import base64
import time
import sys
from Crypto.Cipher import AES
import os
import gc

SESSION_KEY = bytes.fromhex("D53F7A8E9C4B1E7FA2D4768B1C3A9F42E6578D9F3C4B8A2F91B7D6A4C53E7F89")

WARMUP_ITERATIONS = 5
ITERATIONS = 20
DEFAULT_FILE_PATH = "1MB_binary_data.bin"  

class SecureSender:
    def __init__(self):
        self.symmetric_key = SESSION_KEY
        self.socket = None
        self.encryption_times = []
        self.transmission_times = []
        self.file_sizes = []
        self.encrypted_sizes = []
        self.current_iteration = 0
        self.is_warmup = True
        self.file_content = None
        self.file_name = None
        self.receiver_ip = None
        self.port = 5000

    def start_sending(self, receiver_ip, port=5000, file_path=None):
        try:
            self.receiver_ip = receiver_ip
            self.port = port
            
            target_file = file_path if file_path else DEFAULT_FILE_PATH
            self.load_file(target_file)

            print(f"Target receiver: {receiver_ip}:{port}")
            print(f"Running {WARMUP_ITERATIONS} warmup iterations followed by {ITERATIONS} benchmark iterations")

            self.run_iterations()
            self.print_final_stats()
            
        except Exception as e:
            print(f"Error: {e}")

    def connect_to_receiver(self):
        try:
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect((self.receiver_ip, self.port))
            return socket_obj
        except Exception as e:
            print(f"Connection error: {e}")
            return None

    def close_connection(self, socket_obj):
        if socket_obj:
            socket_obj.close()

    def encrypt_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return base64.b64encode(nonce + ciphertext + tag).decode('utf-8')

    def load_file(self, file_path):
        try:
            self.file_name = os.path.basename(file_path)
            self.file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as file:
                self.file_content = file.read()
                
            print(f"Loaded file: {self.file_name}, size: {self.file_size} bytes")
            
        except Exception as e:
            print(f"Error loading file: {e}")
            sys.exit(1)

    def run_iterations(self):
        total_iterations = WARMUP_ITERATIONS + ITERATIONS
        self.current_iteration = 0
        self.is_warmup = True
        
        for i in range(total_iterations):
            if self.is_warmup and i >= WARMUP_ITERATIONS:
                self.is_warmup = False
                self.current_iteration = 0
                print("Warmup completed, starting benchmark iterations")
            
            phase = "WARMUP" if self.is_warmup else "BENCHMARK"
            current = self.current_iteration + 1
            total = WARMUP_ITERATIONS if self.is_warmup else ITERATIONS
            print(f"{phase} iteration {current}/{total}")
            
            gc.collect()

            encryption_time, encrypted_size, transmission_time = self.send_file()

            if not self.is_warmup:
                self.encryption_times.append(encryption_time)
                self.transmission_times.append(transmission_time)
                self.file_sizes.append(len(self.file_content))
                self.encrypted_sizes.append(encrypted_size)

            self.current_iteration += 1

        self.send_completion_signal()

    def send_file(self):
        try:
            b64_content = base64.b64encode(self.file_content).decode('utf-8')
            start_time = time.perf_counter()
            encrypted_file = self.encrypt_message(b64_content)
            encrypted_file_bytes = encrypted_file.encode('utf-8')
            end_time = time.perf_counter()
            encryption_time = (end_time - start_time) * 1e6 
            
            encrypted_size = len(encrypted_file_bytes)

            transmission_start = time.perf_counter()

            socket_obj = self.connect_to_receiver()
            if not socket_obj:
                return 0, 0, 0
                
            header = f"FILE:{self.file_name}:{encrypted_size}:{self.current_iteration}:{1 if self.is_warmup else 0}\n"
            socket_obj.sendall(header.encode('utf-8'))
            socket_obj.sendall(encrypted_file_bytes)

            ack_data = socket_obj.recv(1024).decode('utf-8')
            
            transmission_end = time.perf_counter()

            self.close_connection(socket_obj)
            
            transmission_time = (transmission_end - transmission_start) * 1e6 

            print(f"  Encryption: {encryption_time:.2f} μs, Transmission: {transmission_time:.2f} μs")
            
            return encryption_time, encrypted_size, transmission_time
            
        except Exception as e:
            print(f"Error sending file: {e}")
            return 0, 0, 0

    def send_completion_signal(self):
        try:
            socket_obj = self.connect_to_receiver()
            if socket_obj:
                socket_obj.sendall("COMPLETE".encode('utf-8'))
                print("Sent completion signal to receiver")
                self.close_connection(socket_obj)
        except Exception as e:
            print(f"Error sending completion signal: {e}")

    def print_final_stats(self):
        if not self.encryption_times:
            print("No benchmark data collected.")
            return
            
        avg_encryption = sum(self.encryption_times) / len(self.encryption_times)
        avg_transmission = sum(self.transmission_times) / len(self.transmission_times)
        avg_file_size = sum(self.file_sizes) / len(self.file_sizes)
        avg_encrypted_size = sum(self.encrypted_sizes) / len(self.encrypted_sizes)
        
        print("\n===== SENDER STATISTICS =====")
        print(f"File: {self.file_name}")
        print(f"Average original size: {avg_file_size:.0f} bytes")
        print(f"Average encrypted size: {avg_encrypted_size:.0f} bytes")
        print(f"Average encryption time: {avg_encryption:.2f} microseconds")
        print(f"Average transmission time: {avg_transmission:.2f} microseconds")
        print(f"Total iterations: {len(self.encryption_times)}")
        print("============================\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sender.py <receiver_ip> [file_path]")
        sys.exit(1)
        
    receiver_ip = sys.argv[1]
    file_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    sender = SecureSender()
    sender.start_sending(receiver_ip, file_path=file_path)