import socket
import json
import hashlib
import time
import statistics
import os
import gc
import asyncio

DEFAULT_PSK = "650f641e0666d6e703876de63c61f80b482cdbdc213016dbb582b58c95fa2ceb"
DEFAULT_PORT = 12345
NUM_TESTS = 100

metrics = {
    'connection_times': [],
    'authentication_times': [],
    'total_round_times': []
}

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

async def run_authentication_round(receiver_ip, port, psk, round_num):
    gc.collect()

    psk_hash = hashlib.sha256(psk.encode()).hexdigest()
    
    try:
        total_start_time = time.time_ns()

        conn_start_time = time.time_ns()
        reader, writer = await asyncio.open_connection(receiver_ip, port)
        conn_end_time = time.time_ns()
        metrics['connection_times'].append(conn_end_time - conn_start_time)

        auth_start_time = time.time_ns()

        auth_data = {
            'request': 'authenticate',
            'psk_hash': psk_hash,
            'round': round_num
        }

        writer.write(json.dumps(auth_data).encode())
        await writer.drain()

        auth_end_time = time.time_ns()
        metrics['authentication_times'].append(auth_end_time - auth_start_time)

        total_end_time = time.time_ns()
        metrics['total_round_times'].append(total_end_time - total_start_time)
        
        writer.close()
        await writer.wait_closed()
        
        return True
    except Exception as e:
        print(f"Connection error: {e}")
        return False

async def start_sender(receiver_ip, port=DEFAULT_PORT, psk=DEFAULT_PSK):
    gc.collect()
    
    print(f"Starting authentication benchmark - Sender")
    print(f"Target: {receiver_ip}:{port}")
    print(f"Will perform {NUM_TESTS} authentication rounds")
    
    successful_rounds = 0
    current_round = 0
    
    while successful_rounds < NUM_TESTS:
        try:
            if await run_authentication_round(receiver_ip, port, psk, current_round):
                successful_rounds += 1
            current_round += 1
            await asyncio.sleep(1)  
        except Exception as e:
            print(f"Round error: {e}")
            await asyncio.sleep(2)  
    
    print("\nAll authentication rounds completed")
    display_benchmark_results()

def display_benchmark_results():
    print("\n" + "="*50)
    print("SENDER PSK AUTHENTICATION BENCHMARK RESULTS")
    print("="*50)
    
    metrics_to_display = [
        ("Connection Time", metrics.get('connection_times', [])),
        ("Authentication Processing Time", metrics.get('authentication_times', [])),
        ("Total Round Time", metrics.get('total_round_times', []))
    ]
    
    for name, values in metrics_to_display:
        if values:
            values_us = [value / 1000 for value in values]
            avg_us = statistics.mean(values_us)
            print(f"{name}: {avg_us:.2f} μs (average)")
        else:
            print(f"{NameError}: No data collected")
        print("-"*50)
    
    print("="*50)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Run authentication benchmark - Sender')
    parser.add_argument('receiver_ip', help='IP address of the receiver')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to connect to')
    parser.add_argument('--psk', default=DEFAULT_PSK, help='Pre-shared key for authentication')
    parser.add_argument('--rounds', type=int, default=NUM_TESTS, help='Number of authentication rounds')
    
    args = parser.parse_args()
    NUM_TESTS = args.rounds
    
    print(f"Local IP: {get_local_ip()}")
    
    try:
        asyncio.run(start_sender(args.receiver_ip, args.port, args.psk))
    except KeyboardInterrupt:
        print("\nBenchmark interrupted")
        display_benchmark_results()
