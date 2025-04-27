import socket
import json
import hashlib
import time
import statistics
import os
import gc
import asyncio

DEFAULT_PSK = "650f641e0666d6e703876de63c61f80b482cdbdc213016dbb582b58c95fa2ceb"
DEFAULT_HOST = "0.0.0.0"
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

async def handle_client(reader, writer, psk, psk_hash, completed_rounds):
    total_start_time = time.time_ns()
    
    try:
        # Step 1: Handle connection request
        conn_data = await reader.read(16384)
        conn_request = json.loads(conn_data.decode())
        
        if conn_request.get('request') != 'connect':
            writer.write(json.dumps({'status': 'failed', 'reason': 'invalid_request'}).encode())
            await writer.drain()
            return False
        
        # Send connection acknowledgement
        conn_response = {'status': 'connected', 'round': conn_request.get('round', 0)}
        writer.write(json.dumps(conn_response).encode())
        await writer.drain()
        
        # Step 2: Handle authentication request
        auth_data = await reader.read(16384)
        auth_request = json.loads(auth_data.decode())
        
        auth_start_time = time.time_ns()
        
        if auth_request.get('request') != 'authenticate':
            writer.write(json.dumps({'status': 'failed', 'reason': 'invalid_auth_request'}).encode())
            await writer.drain()
            return False
        
        # Verify PSK hash
        if auth_request.get('psk_hash') == psk_hash:
            # Authentication successful - measure processing time before sending response
            auth_end_time = time.time_ns()
            metrics['authentication_times'].append(auth_end_time - auth_start_time)
            
            response = {
                'status': 'authenticated',
                'round': auth_request.get('round', 0)
            }
            writer.write(json.dumps(response).encode())
            await writer.drain()
            
            total_end_time = time.time_ns()
            current_round = auth_request.get('round', 0)
            print(f"Round {current_round} completed")
            
            completed_rounds.append(current_round)
            return True
        else:
            response = {'status': 'failed', 'reason': 'hash_mismatch'}
            writer.write(json.dumps(response).encode())
            await writer.drain()
            return False
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

    async def connection_handler(reader, writer):
        await handle_client(reader, writer, psk, psk_hash, completed_rounds)
    
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
        ("Authentication Processing Time", metrics.get('authentication_times', []))
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