import socket
import time
import sys
import gc
import base64
from Crypto.Cipher import AES

SESSION_KEY = bytes.fromhex("D53F7A8E9C4B1E7FA2D4768B1C3A9F42E6578D9F3C4B8A2F91B7D6A4C53E7F89")
WARMUP_ITERATIONS = 100
ITERATIONS = 1000

MESSAGES = [
    ("SMALL",  100, b"A" * 100),
    ("MEDIUM", 200, b"B" * 200),
    ("LARGE",  300, b"C" * 300),
]

class MessageSender:
    def __init__(self, receiver_ip, port=5000):
        self.receiver_ip = receiver_ip
        self.port = port
        self.key = SESSION_KEY
        self.sock = None
        self.stats = {
            label: {
                'orig_sizes': [],
                'enc_sizes': [],
                'encryption_times': [],
                'transmission_times': [],         
                'response_processing_times': [],
                'decryption_times': [],
                'total_times': [],
            } for label, _, _ in MESSAGES
        }
        self.conn_time = None

    def connect(self):
        print(f"Connecting to {self.receiver_ip}:{self.port}...")
        t0 = time.perf_counter()
        self.sock = socket.create_connection((self.receiver_ip, self.port))
        self.conn_time = (time.perf_counter() - t0) * 1e6
        print(f"→ Connected in {self.conn_time:.2f} µs\n")

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

    def run(self):
        print(f"Running {WARMUP_ITERATIONS} warm‑up iterations for each message size...\n")
        for label, size, payload in MESSAGES:
            for i in range(1, WARMUP_ITERATIONS + 1):
                encrypted = self.encrypt(payload)
                header = f"MSG:{label}:{i}:{len(encrypted)}\n".encode()
                gc.collect()
                self.sock.sendall(header + encrypted)

                buf = b""
                while b"\n" not in buf:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    buf += chunk
                hdr, rest = buf.split(b"\n", 1)
                parts = hdr.decode().split(":")
                resp_len = int(parts[3])

                buf = rest
                while len(buf) < resp_len:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("Connection closed mid-payload")
                    buf += chunk
                payload_encrypted = buf[:resp_len]
                self.decrypt(payload_encrypted)

                self.sock.sendall(b'A')

        print("Warm‑up complete. Starting main iterations...\n")

        for label, size, payload in MESSAGES:
            print(f"Processing {label} messages ({size} bytes)...")
            for i in range(1, ITERATIONS + 1):
                t_round_start = time.perf_counter()

                t0 = time.perf_counter()
                encrypted = self.encrypt(payload)
                t_enc = (time.perf_counter() - t0) * 1e6

                header = f"MSG:{label}:{i}:{len(encrypted)}\n".encode()
                gc.collect()
                t_tx_start = time.perf_counter()
                self.sock.sendall(header + encrypted)

                first_response = self.sock.recv(1)
                t_tx_end = time.perf_counter()
                if not first_response:
                    raise ConnectionError("Connection closed")
                t_tx = (t_tx_end - t_tx_start) * 1e6

                t_resp_start = time.perf_counter()

                buf = first_response
                while b"\n" not in buf:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    buf += chunk
                hdr, rest = buf.split(b"\n", 1)
                parts = hdr.decode().split(":")
                resp_len = int(parts[3])

                buf = rest
                while len(buf) < resp_len:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("Connection closed mid-payload")
                    buf += chunk
                payload_encrypted = buf[:resp_len]

                t_resp = (time.perf_counter() - t_resp_start) * 1e6

                t0 = time.perf_counter()
                plaintext = self.decrypt(payload_encrypted)
                t_dec = (time.perf_counter() - t0) * 1e6

                self.sock.sendall(b'A')

                t_total = (time.perf_counter() - t_round_start) * 1e6

                if plaintext != payload:
                    print(f"WARNING: mismatch on {label} message {i}")

                self.stats[label]['orig_sizes'].append(size)
                self.stats[label]['enc_sizes'].append(len(encrypted))
                self.stats[label]['encryption_times'].append(t_enc)
                self.stats[label]['transmission_times'].append(t_tx)
                self.stats[label]['response_processing_times'].append(t_resp)
                self.stats[label]['decryption_times'].append(t_dec)
                self.stats[label]['total_times'].append(t_total)

                if i % 10 == 0:
                    print(f"  Completed {i}/{ITERATIONS} iterations")

        self.sock.close()
        self.print_summary()

    def print_summary(self):
        print("\n===== SENDER BENCHMARK SUMMARY =====")
        print(f"Connection establishment time: {self.conn_time:.2f} µs\n")
        for label, _, _ in MESSAGES:
            data = self.stats[label]
            n = len(data['orig_sizes'])
            print(f"----- {label} MESSAGE RESULTS ({n} iterations) -----")
            print(f"Original size:            {sum(data['orig_sizes'])/n:.2f} bytes")
            print(f"Encrypted size:           {sum(data['enc_sizes'])/n:.2f} bytes")
            print(f"Encryption time:          {sum(data['encryption_times'])/n:.2f} µs")
            print(f"Message transmission time: {sum(data['transmission_times'])/n:.2f} µs")
            print(f"Response processing time: {sum(data['response_processing_times'])/n:.2f} µs")
            print(f"Decryption time:          {sum(data['decryption_times'])/n:.2f} µs")
            print(f"Total round‑trip time:    {sum(data['total_times'])/n:.2f} µs")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sender.py <receiver_ip>")
        sys.exit(1)
    gc.collect()
    sender = MessageSender(sys.argv[1])
    sender.connect()
    sender.run()