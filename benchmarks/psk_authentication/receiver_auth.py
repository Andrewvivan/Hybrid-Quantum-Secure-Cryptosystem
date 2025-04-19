import socket
import json
import hashlib
import time
import statistics
import os
import gc
import asyncio
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

DEFAULT_PSK = "650f641e0666d6e703876de63c61f80b482cdbdc213016dbb582b58c95fa2ceb"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12345
NUM_TESTS = 100

metrics = {
    'connection_times': [],
    'authentication_times': [],
    'waiting_times': [],
    'total_round_times': []
}

def derive_aes_key(psk):
    return hashlib.sha256(psk.encode()).digest()

def encrypt_data(data, key):
    if isinstance(data, str):
        data = data.encode()

    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return {
        'iv': iv.hex(),
        'data': encrypted_data.hex()
    }

def decrypt_data(encrypted_dict, key):
    iv = bytes.fromhex(encrypted_dict['iv'])
    encrypted_data = bytes.fromhex(encrypted_dict['data'])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return "127.0.0.1"

async def handle_auth_request(reader, writer, psk, psk_hash, completed_rounds, connection_start_time):
    connection_end_time = time.time_ns()
    connection_time = connection_end_time - connection_start_time
    metrics['connection_times'].append(connection_time)

    total_start_time = time.time_ns()
    
    try:
        waiting_start_time = time.time_ns()
        data = await reader.read(16384)
        waiting_end_time = time.time_ns()

        metrics['waiting_times'].append(waiting_end_time - waiting_start_time)

        auth_start_time = time.time_ns()
        
        received_data = json.loads(data.decode())
        
        if 'request' in received_data and received_data['request'] == 'authenticate':
            if received_data['psk_hash'] == psk_hash:
                aes_key = derive_aes_key(psk)
                encrypted_sender_ip = received_data.get('sender_ip', {})
                
                try:
                    sender_ip = decrypt_data(encrypted_sender_ip, aes_key)
                    encrypted_receiver_ip = encrypt_data(get_local_ip(), aes_key)
                    
                    response = {
                        'status': 'authenticated',
                        'receiver_ip': encrypted_receiver_ip,
                        'round': received_data.get('round', 0)
                    }

                    auth_end_time = time.time_ns()
                    auth_time_ns = (auth_end_time - auth_start_time)
                    metrics['authentication_times'].append(auth_time_ns)

                    writer.write(json.dumps(response).encode())
                    await writer.drain()

                    total_end_time = time.time_ns()
                    total_time_ns = (total_end_time - total_start_time)
                    metrics['total_round_times'].append(total_time_ns)
                    
                    current_round = received_data.get('round', 0)
                    print(f"Round {current_round} completed")
                    
                    completed_rounds.append(current_round)
                    return True
                except Exception as e:
                    response = {'status': 'failed', 'error': str(e)}
                    writer.write(json.dumps(response).encode())
                    await writer.drain()
            else:
                response = {'status': 'failed', 'reason': 'hash_mismatch'}
                writer.write(json.dumps(response).encode())
                await writer.drain()
    except Exception as e:
        print(f"Error processing request: {e}")
    finally:
        writer.close()
    
    return False

async def start_receiver(host=DEFAULT_HOST, port=DEFAULT_PORT, psk=DEFAULT_PSK):
    gc.collect()

    psk_hash = hashlib.sha256(psk.encode()).hexdigest()
    
    print(f"Receiver listening on {host}:{port}")
    print(f"Will perform {NUM_TESTS} authentication rounds")
    
    completed_rounds = []

    connection_start_time = time.time_ns()

    first_connection_received = False
    
    async def connection_handler(reader, writer):
        nonlocal first_connection_received
        if not first_connection_received:
            first_connection_received = True
        await handle_auth_request(reader, writer, psk, psk_hash, completed_rounds, connection_start_time)
    
    server = await asyncio.start_server(
        connection_handler,
        host,
        port
    )
    
    async with server:
        try:
            server_task = asyncio.create_task(server.serve_forever())

            while len(completed_rounds) < NUM_TESTS:
                print(f"Waiting for connections... ({len(completed_rounds)}/{NUM_TESTS})")
                await asyncio.sleep(1) 

            server_task.cancel()
            
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server.close()
            await server.wait_closed()
    
    print("\nAll authentication rounds completed")
    display_benchmark_results()

def display_benchmark_results():
    print("\n" + "="*50)
    print("RECEIVER PSK AUTHENTICATION BENCHMARK RESULTS")
    print("="*50)
    
    metrics_to_display = [
        ("Connection Time", metrics.get('connection_times', [])),
        ("Authentication Processing Time", metrics.get('authentication_times', [])),
        ("Waiting Time", metrics.get('waiting_times', [])),
        ("Total Round Time", metrics.get('total_round_times', []))
    ]
    
    for name, values in metrics_to_display:
        if values:
            values_us = [value / 1000 for value in values]
            avg_us = statistics.mean(values_us)
            print(f"{name}: {avg_us:.2f} μs (average)")
        else:
            print(f"{name}: No data collected")
        print("-"*50)
    
    print("="*50)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Run authentication benchmark - Receiver')
    parser.add_argument('--host', default=DEFAULT_HOST, help='Host IP to listen on')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to listen on')
    parser.add_argument('--psk', default=DEFAULT_PSK, help='Pre-shared key for authentication')
    parser.add_argument('--rounds', type=int, default=NUM_TESTS, help='Number of authentication rounds')
    
    args = parser.parse_args()
    NUM_TESTS = args.rounds
    
    print("Starting authentication benchmark - Receiver")
    print(f"Local IP: {get_local_ip()}")
    
    try:
        asyncio.run(start_receiver(args.host, args.port, args.psk))
    except KeyboardInterrupt:
        print("\nBenchmark interrupted")
        display_benchmark_results()