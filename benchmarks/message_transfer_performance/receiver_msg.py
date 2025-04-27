import socket
import time
import gc
import base64
from Crypto.Cipher import AES

SESSION_KEY = bytes.fromhex("D53F7A8E9C4B1E7FA2D4768B1C3A9F42E6578D9F3C4B8A2F91B7D6A4C53E7F89")
WARMUP_ITERATIONS = 100
ITERATIONS = 1000
MESSAGES = [("SMALL", 100), ("MEDIUM", 200), ("LARGE", 300)]


class MessageReceiver:
    def __init__(self, port=5000):
        self.port = port
        self.key = SESSION_KEY
        self.sock = None
        self.client = None
        self.conn_time = None

        self.stats = {
            label: {
                'orig_sizes': [],     
                'enc_sizes': [],           
                'decryption_times': [], 
                'encryption_times': [],   
                'transmission_times': [],   
                'total_processing_times': [], 
            } for label, _ in MESSAGES
        }

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(1)
        print(f"Listening on port {self.port}...")

        t0 = time.perf_counter()
        self.client, addr = self.sock.accept()
        self.conn_time = (time.perf_counter() - t0) * 1e6
        print(f"→ Connection from {addr[0]}:{addr[1]} in {self.conn_time:.2f} µs\n")

        self.handle_messages()

        self.client.close()
        self.sock.close()
        self.print_summary()

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM)
        nonce = cipher.nonce
        ct, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(nonce + ct + tag)

    def decrypt(self, data: bytes) -> bytes:
        raw = base64.b64decode(data)
        nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    def handle_messages(self):
        print(f"Running {WARMUP_ITERATIONS} warm‑up iterations for each message size...\n")
        for label, _ in MESSAGES:
            for idx in range(1, WARMUP_ITERATIONS + 1):
                buf = b""
                while b"\n" not in buf:
                    chunk = self.client.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                hdr, buf = buf.split(b"\n", 1)
                parts = hdr.decode().split(":")
                length = int(parts[3])

                while len(buf) < length:
                    chunk = self.client.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                encrypted = buf[:length]
                buf = buf[length:]

                plaintext = self.decrypt(encrypted)
                resp_encrypted = self.encrypt(plaintext)

                header = f"MSGRESP:{label}:{idx}:{len(resp_encrypted)}\n".encode()
                self.client.sendall(header + resp_encrypted)

                self.client.recv(1)

        print("Warm‑up complete. Starting main measurements...\n")

        for label, _ in MESSAGES:
            for idx in range(1, ITERATIONS + 1):
                t_process_start = time.perf_counter()

                buf = b""
                while b"\n" not in buf:
                    chunk = self.client.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                hdr, buf = buf.split(b"\n", 1)
                parts = hdr.decode().split(":")
                length = int(parts[3])

                while len(buf) < length:
                    chunk = self.client.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                encrypted = buf[:length]
                buf = buf[length:]

                t0 = time.perf_counter()
                plaintext = self.decrypt(encrypted)
                t_dec = (time.perf_counter() - t0) * 1e6

                t0 = time.perf_counter()
                resp_encrypted = self.encrypt(plaintext)
                t_enc = (time.perf_counter() - t0) * 1e6

                t0 = time.perf_counter()
                header = f"MSGRESP:{label}:{idx}:{len(resp_encrypted)}\n".encode()
                self.client.sendall(header + resp_encrypted)

                ack = self.client.recv(1)
                if not ack:
                    print("Connection closed during acknowledgement wait")
                    return
                    
                t_tx = (time.perf_counter() - t0) * 1e6

                t_total = (time.perf_counter() - t_process_start) * 1e6

                self.stats[label]['orig_sizes'].append(len(plaintext))
                self.stats[label]['enc_sizes'].append(len(encrypted))
                self.stats[label]['decryption_times'].append(t_dec)
                self.stats[label]['encryption_times'].append(t_enc)
                self.stats[label]['transmission_times'].append(t_tx)
                self.stats[label]['total_processing_times'].append(t_total)

                if idx % 10 == 0:
                    print(f"Processed {label} iteration {idx}/{ITERATIONS}")

    def print_summary(self):
        print("\n===== RECEIVER BENCHMARK SUMMARY =====")
        print(f"Connection establishment time: {self.conn_time:.2f} µs")

        for label, _ in MESSAGES:
            data = self.stats[label]
            n = len(data['orig_sizes'])
            print(f"\n----- {label} MESSAGE RESULTS ({n} iterations) -----")
            print(f"Original message size:     {sum(data['orig_sizes'])/n:.2f} bytes")
            print(f"Encrypted message size:    {sum(data['enc_sizes'])/n:.2f} bytes")
            print(f"Message decryption time:   {sum(data['decryption_times'])/n:.2f} µs")
            print(f"Response encryption time:  {sum(data['encryption_times'])/n:.2f} µs")
            print(f"Message transmission time: {sum(data['transmission_times'])/n:.2f} µs")
            print(f"Total processing time:     {sum(data['total_processing_times'])/n:.2f} µs")


if __name__ == "__main__":
    gc.collect()
    receiver = MessageReceiver()
    receiver.start()