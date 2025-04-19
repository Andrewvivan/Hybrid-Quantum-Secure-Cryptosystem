import socket
import base64
import time
import sys
from Crypto.Cipher import AES
import os
import threading
import datetime
import gc

SESSION_KEY = bytes.fromhex("D53F7A8E9C4B1E7FA2D4768B1C3A9F42E6578D9F3C4B8A2F91B7D6A4C53E7F89")

WARMUP_ITERATIONS = 2
ITERATIONS = 10

DEFAULT_FILE_PATH = r"C:\.pdf"  

class SimpleSecureSender:
    def __init__(self):
        self.symmetric_key = SESSION_KEY
        self.socket = None
        self.sequence_number = 0
        self.logs = []
        self.start_time = None
        self.connection_time = None
        self.current_iteration = 0
        self.benchmarks = []
        self.is_warmup = True
        self.file_content = None
        self.file_name = None
        self.file_type = None
        self.original_file_size = None

    def connect_to_receiver(self, receiver_ip, port=5000, file_path=None):
        try:
            target_file = file_path if file_path else DEFAULT_FILE_PATH

            self.load_file(target_file)

            self.start_time = time.perf_counter()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((receiver_ip, port))
            self.connection_time = (time.perf_counter() - self.start_time) * 1e6  
            print(f"Connected to {receiver_ip}:{port} in {self.connection_time:.2f} microseconds")
            print(f"Running {WARMUP_ITERATIONS} warmup iterations followed by {ITERATIONS} benchmark iterations")

            self.run_iterations()

            self.print_final_stats()
            
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.close_connection()

    def close_connection(self):
        print("Closing connection...")
        if self.socket:
            self.socket.close()
            self.socket = None
        print("Connection closed.")

    def encrypt_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return base64.b64encode(nonce + ciphertext + tag).decode('utf-8')

    def decrypt_message(self, ciphertext):
        raw = base64.b64decode(ciphertext)
        nonce = raw[:16]
        ciphertext_part = raw[16:-16]
        tag = raw[-16:]
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext_part, tag).decode('utf-8')

    def load_file(self, file_path):
        try:
            self.file_name = os.path.basename(file_path)
            self.file_size = os.path.getsize(file_path)
            self.file_type = os.path.splitext(self.file_name)[1] or "unknown"
            self.original_file_size = self.file_size

            with open(file_path, 'rb') as file:
                self.file_content = file.read()
                
            print(f"Loaded file: {self.file_name}, size: {self.file_size} bytes, type: {self.file_type}")
            
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
            print(f"{phase} iteration {self.current_iteration + 1}/{WARMUP_ITERATIONS if self.is_warmup else ITERATIONS}")

            gc.collect()

            protocol_start_time = time.perf_counter()

            self.send_file()

            self.wait_for_response()

            protocol_end_time = time.perf_counter()
            protocol_time = (protocol_end_time - protocol_start_time) * 1e6

            if self.benchmarks and self.benchmarks[-1]["iteration"] == self.current_iteration and self.benchmarks[-1]["is_warmup"] == self.is_warmup:
                self.benchmarks[-1]["total_protocol_time_us"] = protocol_time
            
            self.current_iteration += 1

            time.sleep(0.1)

        self.send_completion_signal()

    def send_file(self):
        try:
            start_time = time.perf_counter()
            b64_content = base64.b64encode(self.file_content).decode('utf-8')
            encrypted_file = self.encrypt_message(b64_content)
            encrypted_file_bytes = encrypted_file.encode('utf-8')
            end_time = time.perf_counter()
            encryption_time = (end_time - start_time) * 1e6  
            
            encrypted_size = len(encrypted_file_bytes)

            benchmark_data = {
                "iteration": self.current_iteration,
                "is_warmup": self.is_warmup,
                "file_type": self.file_type,
                "original_size_bytes": self.original_file_size,
                "encrypted_size_bytes": encrypted_size,
                "encryption_time_us": encryption_time,
            }
            self.benchmarks.append(benchmark_data)

            log_entry = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": "File Sent",
                "file_name": self.file_name,
                "original_size_bytes": self.original_file_size,
                "encrypted_size_bytes": encrypted_size,
                "file_type": self.file_type,
                "encryption_time_us": encryption_time
            }
            self.logs.append(log_entry)

            header = f"FILE:{self.file_name}:{len(encrypted_file_bytes)}:{self.current_iteration}:{1 if self.is_warmup else 0}\n"
            transmission_start = time.perf_counter()
            self.socket.sendall(header.encode('utf-8'))
            self.socket.sendall(encrypted_file_bytes)

            ack_data = self.socket.recv(1024)
            transmission_end = time.perf_counter()
            
            if not ack_data.startswith(b"ACK:"):
                print("Warning: No proper acknowledgment received")
                return
                
            transmission_time = (transmission_end - transmission_start) * 1e6  

            benchmark_data["transmission_time_us"] = transmission_time
            
        except Exception as e:
            print(f"Error sending file: {e}")

    def wait_for_response(self):
        try:
            recv_buffer = ""
            file_reception_start = None
            
            while True:
                data = self.socket.recv(16384)
                if not data:
                    break

                if data == b"DONE":
                    print("Receiver has completed all iterations. Exiting...")
                    return

                gc.collect()

                if not recv_buffer and data.decode('utf-8', errors='ignore').startswith("FILE:"):
                    file_reception_start = time.perf_counter()
                
                recv_buffer += data.decode('utf-8')
                
                if recv_buffer.startswith("FILE:"):
                    newline_index = recv_buffer.find("\n")
                    if newline_index == -1:
                        continue
                    header = recv_buffer[:newline_index]
                    parts = header.split(":")
                    if len(parts) < 3:
                        print("Invalid file header received.")
                        recv_buffer = ""
                        continue
                    
                    try:
                        data_length = int(parts[2])
                    except ValueError:
                        print("Invalid file length received.")
                        recv_buffer = ""
                        continue
                        
                    total_length = newline_index + 1 + data_length
                    if len(recv_buffer) < total_length:
                        continue

                    file_reception_end = time.perf_counter()
                    file_reception_time = (file_reception_end - file_reception_start) * 1e6 
                    
                    encrypted_file = recv_buffer[newline_index+1:total_length]
                    recv_buffer = recv_buffer[total_length:]

                    start_time = time.perf_counter()
                    try:
                        decrypted_file_content = self.decrypt_message(encrypted_file)
                        file_content = base64.b64decode(decrypted_file_content)
                        is_decrypted = True
                    except Exception as e:
                        print(f"Decryption failed: {e}")
                        continue
                    end_time = time.perf_counter()
                    decryption_time = (end_time - start_time) * 1e6  
                    
                    encrypted_size = len(encrypted_file)
                    original_size = len(file_content)

                    if self.benchmarks and self.benchmarks[-1]["iteration"] == self.current_iteration and self.benchmarks[-1]["is_warmup"] == self.is_warmup:
                        self.benchmarks[-1]["return_reception_time_us"] = file_reception_time
                        self.benchmarks[-1]["return_decryption_time_us"] = decryption_time
                        self.benchmarks[-1]["return_encrypted_size_bytes"] = encrypted_size
                        self.benchmarks[-1]["return_original_size_bytes"] = original_size

                    log_entry = {
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "event": "File Received Back",
                        "file_name": self.file_name,
                        "encrypted_size_bytes": encrypted_size,
                        "original_size_bytes": original_size,
                        "file_type": self.file_type,
                        "reception_time_us": file_reception_time,
                        "decryption_time_us": decryption_time
                    }
                    self.logs.append(log_entry)

                    self.socket.sendall(f"ACK:{self.current_iteration}:{1 if self.is_warmup else 0}".encode('utf-8'))

                    return
                    
        except Exception as e:
            print(f"Receive error: {e}")

    def send_completion_signal(self):
        try:
            self.socket.sendall("COMPLETE".encode('utf-8'))
            print("Sent completion signal to receiver")
        except Exception as e:
            print(f"Error sending completion signal: {e}")

    def print_final_stats(self):
        benchmark_iterations = [b for b in self.benchmarks if not b["is_warmup"]]
        
        if not benchmark_iterations:
            print("No benchmark data collected.")
            return
            
        encryption_times = [b.get("encryption_time_us", 0) for b in benchmark_iterations]
        transmission_times = [b.get("transmission_time_us", 0) for b in benchmark_iterations]
        return_reception_times = [b.get("return_reception_time_us", 0) for b in benchmark_iterations]
        return_decryption_times = [b.get("return_decryption_time_us", 0) for b in benchmark_iterations]
        protocol_times = [b.get("total_protocol_time_us", 0) for b in benchmark_iterations]

        avg_encryption = sum(encryption_times) / len(encryption_times)
        avg_transmission = sum(transmission_times) / len(transmission_times)
        avg_return_reception = sum(return_reception_times) / len(return_reception_times)
        avg_return_decryption = sum(return_decryption_times) / len(return_decryption_times)
        avg_protocol = sum(protocol_times) / len(protocol_times)
        
        print("\n===== FINAL SENDER STATISTICS =====")
        print(f"File type: {self.file_type}")
        print(f"Original file size: {self.original_file_size} bytes")
        print(f"Connection time: {self.connection_time:.2f} microseconds")
        print(f"Average Encryption Time: {avg_encryption:.2f} microseconds")
        print(f"Average Transmission Time: {avg_transmission:.2f} microseconds")
        print(f"Average Return Reception Time: {avg_return_reception:.2f} microseconds")
        print(f"Average Return Decryption Time: {avg_return_decryption:.2f} microseconds")
        print(f"Average Total Protocol Time: {avg_protocol:.2f} microseconds")
        print("====================================\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sender.py <receiver_ip> [file_path]")
        sys.exit(1)
        
    receiver_ip = sys.argv[1]
    file_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    sender = SimpleSecureSender()
    sender.connect_to_receiver(receiver_ip, file_path=file_path)