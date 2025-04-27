import time
import os
from Crypto.Cipher import AES

SESSION_KEY = bytes.fromhex("D53F7A8E9C4B1E7FA2D4768B1C3A9F42E6578D9F3C4B8A2F91B7D6A4C53E7F89")
BENCHMARK_ITERATIONS = 1  
CHUNK_SIZE = 64 * 1024 * 1024 
FILE_PATH = "25GB_binary_data.bin" 
ENCRYPTED_FILE_PATH = "25GB_binary_data.encrypted" 

class ImprovedEncryptionBenchmark:
    def __init__(self):
        self.symmetric_key = SESSION_KEY
        self.encryption_times = []
        self.decryption_times = []

    def run_benchmark(self):
        try:
            file_name = os.path.basename(FILE_PATH)
            file_size = os.path.getsize(FILE_PATH)
            
            print(f"Running benchmark on file: {file_name}, size: {file_size} bytes")
            print(f"Processing in {CHUNK_SIZE/(1024*1024)}MB chunks")
            print(f"Performing {BENCHMARK_ITERATIONS} benchmark iterations")
            
            for i in range(BENCHMARK_ITERATIONS):
                print(f"\nBenchmark iteration {i+1}/{BENCHMARK_ITERATIONS}")

                self.run_encryption_iteration()

                self.run_decryption_iteration()

            avg_encryption = sum(self.encryption_times) / len(self.encryption_times)
            avg_decryption = sum(self.decryption_times) / len(self.decryption_times)
            
            print("\n=== BENCHMARK RESULTS ===")
            print(f"Average encryption time: {avg_encryption:.2f} ms")
            print(f"Average decryption time: {avg_decryption:.2f} ms")
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if os.path.exists(ENCRYPTED_FILE_PATH):
                try:
                    os.remove(ENCRYPTED_FILE_PATH)
                    print(f"Cleaned up temporary encrypted file: {ENCRYPTED_FILE_PATH}")
                except:
                    print(f"Warning: Could not remove temporary file: {ENCRYPTED_FILE_PATH}")

    def run_encryption_iteration(self):
        total_encryption_time = 0
        total_size = 0

        with open(FILE_PATH, 'rb') as input_file, open(ENCRYPTED_FILE_PATH, 'wb') as output_file:
            while True:
                chunk = input_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                chunk_size = len(chunk)
                total_size += chunk_size

                start_time = time.perf_counter()
                encrypted_data = self.encrypt_chunk(chunk)
                end_time = time.perf_counter()
                
                encryption_time = (end_time - start_time) * 1000  
                total_encryption_time += encryption_time
          
                output_file.write(len(encrypted_data).to_bytes(8, byteorder='big'))  
                output_file.write(encrypted_data)

                del encrypted_data
   
        self.encryption_times.append(total_encryption_time)
        print(f"  Encryption time: {total_encryption_time:.2f} ms for {total_size/(1024*1024*1024):.2f} GB")

    def run_decryption_iteration(self):

        total_decryption_time = 0
        total_size = 0

        with open(ENCRYPTED_FILE_PATH, 'rb') as input_file:
            while True:
                size_bytes = input_file.read(8)
                if not size_bytes or len(size_bytes) < 8:
                    break
                
                chunk_size = int.from_bytes(size_bytes, byteorder='big')
                encrypted_chunk = input_file.read(chunk_size)
                
                if not encrypted_chunk or len(encrypted_chunk) < chunk_size:
                    break
                
                total_size += chunk_size

                start_time = time.perf_counter()
                decrypted_chunk = self.decrypt_chunk(encrypted_chunk)
                end_time = time.perf_counter()
                
                decryption_time = (end_time - start_time) * 1000  
                total_decryption_time += decryption_time

                del decrypted_chunk
                del encrypted_chunk
        
        self.decryption_times.append(total_decryption_time)
        print(f"  Decryption time: {total_decryption_time:.2f} ms for encrypted data")

    def encrypt_chunk(self, data):
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + ciphertext + tag

    def decrypt_chunk(self, encrypted_data):
        nonce = encrypted_data[:16]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[16:-16]
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

if __name__ == "__main__":
    benchmark = ImprovedEncryptionBenchmark()
    benchmark.run_benchmark()