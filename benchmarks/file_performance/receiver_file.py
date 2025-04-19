import socket
import base64
import time
from Crypto.Cipher import AES
import os
import threading
import datetime
import gc

SESSION_KEY = bytes.fromhex("D53F7A8E9C4B1E7FA2D4768B1C3A9F42E6578D9F3C4B8A2F91B7D6A4C53E7F89")

WARMUP_ITERATIONS = 2
ITERATIONS = 10

SAVE_DIR = "received_files"

class SimpleSecureReceiver:
    def __init__(self, port=5000):
        self.port = port
        self.symmetric_key = SESSION_KEY
        self.server_socket = None
        self.client_socket = None
        self.sequence_number = 0
        self.logs = []
        self.start_time = None
        self.connection_time = None
        self.current_iteration = 0
        self.benchmarks = []
        self.is_warmup = True

        os.makedirs(SAVE_DIR, exist_ok=True)

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(1)
            print(f"Receiver started on port {self.port}")
            print(f"Local IP: {self.get_local_ip()}")
            print(f"Running {WARMUP_ITERATIONS} warmup iterations followed by {ITERATIONS} benchmark iterations")
            
            self.start_time = time.perf_counter()
            self.client_socket, client_address = self.server_socket.accept()
            self.connection_time = (time.perf_counter() - self.start_time) * 1e6  # Convert to microseconds
            print(f"Connection established with {client_address[0]}:{client_address[1]} in {self.connection_time:.2f} microseconds")

            self.process_communications()

            self.print_final_stats()
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.close_connection()

    def close_connection(self):
        print("Closing connection...")
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        print("Connection closed.")

    def get_local_ip(self):
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except Exception:
            return "Unable to retrieve IP"

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

    def process_communications(self):
        recv_buffer = ""
        file_reception_start = None
        
        while True:
            try:
                data = self.client_socket.recv(16384)
                if not data:
                    print("Connection closed by client")
                    break

                if data == b"COMPLETE":
                    print("Sender has completed all iterations")
                    self.print_final_stats()
                    break

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

                    file_name = parts[1]
                    try:
                        data_length = int(parts[2])

                        if len(parts) >= 5:
                            iteration = int(parts[3])
                            is_warmup = bool(int(parts[4]))
                            self.current_iteration = iteration
                            self.is_warmup = is_warmup
                    except ValueError:
                        print("Invalid file header values received.")
                        recv_buffer = ""
                        continue
                        
                    total_length = newline_index + 1 + data_length
                    if len(recv_buffer) < total_length:
                        continue

                    protocol_start_time = time.perf_counter()

                    file_reception_end = time.perf_counter()
                    file_reception_time = (file_reception_end - file_reception_start) * 1e6  
                    
                    encrypted_file = recv_buffer[newline_index+1:total_length]
                    recv_buffer = recv_buffer[total_length:]

                    start_time = time.perf_counter()
                    try:
                        decrypted_file_content = self.decrypt_message(encrypted_file)
                        file_content = base64.b64decode(decrypted_file_content)
                    except Exception as e:
                        print(f"Decryption failed: {e}")
                        continue
                    end_time = time.perf_counter()
                    decryption_time = (end_time - start_time) * 1e6  
                    
                    encrypted_size = len(encrypted_file)
                    original_size = len(file_content)
                    file_ext = os.path.splitext(file_name)[1] or "unknown"

                    save_path = os.path.join(SAVE_DIR, f"{self.current_iteration}_{file_name}")
                    with open(save_path, 'wb') as f:
                        f.write(file_content)

                    self.client_socket.sendall(f"ACK:{self.current_iteration}:{1 if self.is_warmup else 0}".encode('utf-8'))

                    benchmark_data = {
                        "iteration": self.current_iteration,
                        "is_warmup": self.is_warmup,
                        "file_type": file_ext,
                        "original_size_bytes": original_size,
                        "encrypted_size_bytes": encrypted_size,
                        "reception_time_us": file_reception_time,
                        "decryption_time_us": decryption_time,
                    }
                    self.benchmarks.append(benchmark_data)

                    log_entry = {
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "event": "File Received",
                        "file_name": file_name,
                        "encrypted_size_bytes": encrypted_size,
                        "original_size_bytes": original_size,
                        "file_type": file_ext,
                        "reception_time_us": file_reception_time,
                        "decryption_time_us": decryption_time
                    }
                    self.logs.append(log_entry)

                    self.send_file_back(file_name, file_content, benchmark_data, protocol_start_time)

                    phase = "WARMUP" if self.is_warmup else "BENCHMARK"
                    print(f"{phase} iteration {self.current_iteration + 1}/{WARMUP_ITERATIONS if self.is_warmup else ITERATIONS}")
                    
                else:
                    if recv_buffer:
                        try:
                            decrypted_message = self.decrypt_message(recv_buffer)
                            print(f"Received message: {decrypted_message}")
                        except Exception:
                            print("Message rejected due to key mismatch.")
                        recv_buffer = ""
            except Exception as e:
                print(f"Receive error: {e}")
                break

    def send_file_back(self, file_name, file_content, benchmark_data, protocol_start_time):
        try:
            gc.collect()

            start_time = time.perf_counter()
            b64_content = base64.b64encode(file_content).decode('utf-8')
            encrypted_file = self.encrypt_message(b64_content)
            encrypted_file_bytes = encrypted_file.encode('utf-8')
            end_time = time.perf_counter()
            encryption_time = (end_time - start_time) * 1e6  
            
            file_size = len(encrypted_file_bytes)
            original_size = len(file_content)
            file_ext = os.path.splitext(file_name)[1] or "unknown"

            benchmark_data["return_encryption_time_us"] = encryption_time
            benchmark_data["return_encrypted_size_bytes"] = file_size

            log_entry = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": "File Sent Back",
                "file_name": file_name,
                "original_size_bytes": original_size,
                "encrypted_size_bytes": file_size,
                "file_type": file_ext,
                "encryption_time_us": encryption_time
            }
            self.logs.append(log_entry)

            header = f"FILE:{file_name}:{len(encrypted_file_bytes)}:{self.current_iteration}:{1 if self.is_warmup else 0}\n"
            transmission_start = time.perf_counter()
            self.client_socket.sendall(header.encode('utf-8'))
            self.client_socket.sendall(encrypted_file_bytes)

            ack_data = self.client_socket.recv(1024)
            transmission_end = time.perf_counter()
            
            if not ack_data.startswith(b"ACK:"):
                print("Warning: No proper acknowledgment received")
                return
                
            transmission_time = (transmission_end - transmission_start) * 1e6  

            benchmark_data["return_transmission_time_us"] = transmission_time

            protocol_end_time = time.perf_counter()
            protocol_time = (protocol_end_time - protocol_start_time) * 1e6  
            benchmark_data["total_protocol_time_us"] = protocol_time
            
        except Exception as e:
            print(f"Error sending file back: {e}")

    def print_final_stats(self):
        benchmark_iterations = [b for b in self.benchmarks if not b["is_warmup"]]
        
        if not benchmark_iterations:
            print("No benchmark data collected.")
            return
            
        reception_times = [b.get("reception_time_us", 0) for b in benchmark_iterations]
        decryption_times = [b.get("decryption_time_us", 0) for b in benchmark_iterations]
        return_encryption_times = [b.get("return_encryption_time_us", 0) for b in benchmark_iterations]
        return_transmission_times = [b.get("return_transmission_time_us", 0) for b in benchmark_iterations]
        protocol_times = [b.get("total_protocol_time_us", 0) for b in benchmark_iterations]

        avg_reception = sum(reception_times) / len(reception_times)
        avg_decryption = sum(decryption_times) / len(decryption_times)
        avg_return_encryption = sum(return_encryption_times) / len(return_encryption_times)
        avg_return_transmission = sum(return_transmission_times) / len(return_transmission_times)
        avg_protocol = sum(protocol_times) / len(protocol_times)
        
        print("\n===== FINAL RECEIVER STATISTICS =====")
        print(f"File type: {benchmark_iterations[0]['file_type']}")
        print(f"Original file size: {benchmark_iterations[0]['original_size_bytes']} bytes")
        print(f"Connection time: {self.connection_time:.2f} microseconds")
        print(f"Average Reception Time: {avg_reception:.2f} microseconds")
        print(f"Average Decryption Time: {avg_decryption:.2f} microseconds")
        print(f"Average Return Encryption Time: {avg_return_encryption:.2f} microseconds")
        print(f"Average Return Transmission Time: {avg_return_transmission:.2f} microseconds")
        print(f"Average Total Protocol Time: {avg_protocol:.2f} microseconds")
        print("====================================\n")

        try:
            self.client_socket.sendall(b"DONE")
        except:
            pass

if __name__ == "__main__":
    receiver = SimpleSecureReceiver()
    receiver.start_server()