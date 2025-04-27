import socket
import base64
import time
from Crypto.Cipher import AES
import os
import gc
import threading

SESSION_KEY = bytes.fromhex("D53F7A8E9C4B1E7FA2D4768B1C3A9F42E6578D9F3C4B8A2F91B7D6A4C53E7F89")

WARMUP_ITERATIONS = 5
ITERATIONS = 20
SAVE_DIR = "received_files"

class SecureReceiver:
    def __init__(self, port=5000):
        self.port = port
        self.symmetric_key = SESSION_KEY
        self.server_socket = None
        self.decryption_times = []
        self.file_sizes = []
        self.warmup_received = 0
        self.benchmark_received = 0
        self.is_running = True
        self.lock = threading.Lock()  

        os.makedirs(SAVE_DIR, exist_ok=True)

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5) 
            
            print(f"Receiver started on port {self.port}")
            print(f"Local IP: {self.get_local_ip()}")
            print(f"Waiting for connections...")
            print(f"Expecting {WARMUP_ITERATIONS} warmup iterations followed by {ITERATIONS} benchmark iterations")

            while self.is_running:
                try:
                    self.server_socket.settimeout(1.0)  
                    client_socket, client_address = self.server_socket.accept()
                    print(f"Connection established with {client_address[0]}:{client_address[1]}")

                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                    
            print("Server shutdown complete")
            
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.close_server()

    def close_server(self):
        print("Closing server...")
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        print("Server closed.")
        
    def handle_client(self, client_socket, client_address):
        try:
            recv_buffer = ""
            
            while True:
                data = client_socket.recv(65536)
                if not data:
                    print(f"Connection closed by {client_address[0]}:{client_address[1]}")
                    break

                if data == b"COMPLETE":
                    print("Sender has completed all iterations")
                    self.print_final_stats()
                    self.is_running = False
                    break

                gc.collect()  

                recv_buffer += data.decode('utf-8', errors='ignore')
                
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
                    except ValueError:
                        print("Invalid file header values received.")
                        recv_buffer = ""
                        continue

                    total_length = newline_index + 1 + data_length
                    if len(recv_buffer) < total_length:
                        continue

                    encrypted_file = recv_buffer[newline_index+1:total_length]
                    recv_buffer = recv_buffer[total_length:]

                    client_socket.sendall(f"File received:{iteration}:{1 if is_warmup else 0}".encode('utf-8'))

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
                    
                    with self.lock:
                        if is_warmup:
                            self.warmup_received += 1
                            current = self.warmup_received
                            total = WARMUP_ITERATIONS
                            phase = "WARMUP"
                        else:
                            self.benchmark_received += 1
                            self.decryption_times.append(decryption_time)
                            self.file_sizes.append(original_size)
                            current = self.benchmark_received
                            total = ITERATIONS
                            phase = "BENCHMARK"

                    save_path = os.path.join(SAVE_DIR, f"{phase.lower()}_{current}_{file_name}")
                    with open(save_path, 'wb') as f:
                        f.write(file_content)

                    print(f"{phase} iteration {current}/{total} - Decryption time: {decryption_time:.2f} μs")
                    break  

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()

    def get_local_ip(self):
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except Exception:
            return "Unable to retrieve IP"

    def decrypt_message(self, ciphertext):
        raw = base64.b64decode(ciphertext)
        nonce = raw[:16]
        ciphertext_part = raw[16:-16]
        tag = raw[-16:]
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext_part, tag).decode('utf-8')

    def print_final_stats(self):
        if not self.decryption_times:
            print("No benchmark data collected.")
            return
            
        avg_decryption_time = sum(self.decryption_times) / len(self.decryption_times)
        
        print("\n===== RECEIVER STATISTICS =====")
        print(f"Average file size: {sum(self.file_sizes) / len(self.file_sizes):.0f} bytes")
        print(f"Average decryption time: {avg_decryption_time:.2f} microseconds")
        print(f"Total iterations: {len(self.decryption_times)}")
        print("===============================\n")

if __name__ == "__main__":
    receiver = SecureReceiver()
    receiver.start_server()