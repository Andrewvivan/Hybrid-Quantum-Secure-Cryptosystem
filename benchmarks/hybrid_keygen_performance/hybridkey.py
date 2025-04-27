import time
import re
import gc
import matplotlib.pyplot as plt
from argon2.low_level import hash_secret_raw, Type

def is_valid_binary(s):
    return all(c in '01' for c in s)

def is_valid_hex_32byte(s):
    return bool(re.fullmatch(r'[0-9a-fA-F]{64}', s))


def generate_hybrid_key_16(quantum_key, kyber_key):
    combined = (quantum_key + kyber_key).encode('utf-8')
    salt = bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2")
    return hash_secret_raw(
        secret=combined,
        salt=salt,
        time_cost=4,
        memory_cost=102400,
        parallelism=8,
        hash_len=16,
        type=Type.ID
    )

def generate_hybrid_key_32(quantum_key, kyber_key):
    combined = (quantum_key + kyber_key).encode('utf-8')
    salt = bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2")
    return hash_secret_raw(
        secret=combined,
        salt=salt,
        time_cost=4,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.ID
    )

def generate_hybrid_key_64(quantum_key, kyber_key):
    combined = (quantum_key + kyber_key).encode('utf-8')
    salt = bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2")
    return hash_secret_raw(
        secret=combined,
        salt=salt,
        time_cost=4,
        memory_cost=102400,
        parallelism=8,
        hash_len=64,
        type=Type.ID
    )

def benchmark_keygen_16(quantum_key, kyber_key, iterations=50, warmups=10):
    gc.collect()
    
    for _ in range(warmups):
        generate_hybrid_key_16(quantum_key, kyber_key)
    gc.collect()
    
    total_start = time.perf_counter()
    
    for _ in range(iterations):
        generate_hybrid_key_16(quantum_key, kyber_key)
    
    total_end = time.perf_counter()
    
    avg_time_micro = ((total_end - total_start) / iterations) * 1e6
    total_time_seconds = total_end - total_start
    
    return avg_time_micro, total_time_seconds

def benchmark_keygen_32(quantum_key, kyber_key, iterations=50, warmups=10):
    gc.collect()
    
    for _ in range(warmups):
        generate_hybrid_key_32(quantum_key, kyber_key)
    gc.collect()
    
    total_start = time.perf_counter()
    
    for _ in range(iterations):
        generate_hybrid_key_32(quantum_key, kyber_key)
    
    total_end = time.perf_counter()
    
    avg_time_micro = ((total_end - total_start) / iterations) * 1e6
    total_time_seconds = total_end - total_start
    
    return avg_time_micro, total_time_seconds

def benchmark_keygen_64(quantum_key, kyber_key, iterations=50, warmups=10):
    gc.collect()
    
    for _ in range(warmups):
        generate_hybrid_key_64(quantum_key, kyber_key)

    gc.collect()
    
    total_start = time.perf_counter()
    
    for _ in range(iterations):
        generate_hybrid_key_64(quantum_key, kyber_key)
    
    total_end = time.perf_counter()
    
    avg_time_micro = ((total_end - total_start) / iterations) * 1e6
    total_time_seconds = total_end - total_start
    
    return avg_time_micro, total_time_seconds

def main():
    quantum_key = "010110010011010010111010011011001110100110101001101011001001011010011001011011001010101100110110010101100110110101011001001101101001101100110110100101011001101001011001010110010110010101101001101001011001101001100110101001101011010011010110010101101001"
    kyber_key = "7f8a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f7a8b9c6d5e4f3a2b1c0d7e8f9a"

    if not is_valid_binary(quantum_key):
        print("Error: Hardcoded quantum key is invalid. It must only contain 0s and 1s.")
        return

    if not is_valid_hex_32byte(kyber_key):
        print("Error: Hardcoded Kyber key is invalid. It must be a valid 32-byte (64 hex characters) string.")
        return

    print("[+] Completing hybrid key generation benchmark. Please wait....")

    overall_start = time.perf_counter()

    gc.collect()

    print("\n[+] Benchmarking 16-byte key generation...")
    print("    - Running garbage collector...")
    gc.collect()
    avg_time_16, total_time_16 = benchmark_keygen_16(quantum_key, kyber_key)
    print(f"    - Average time: {avg_time_16:.2f} µs per operation")
    print(f"    - Total time: {total_time_16:.4f} seconds")

    print("\n[+] Benchmarking 32-byte key generation...")
    print("    - Running garbage collector...")
    gc.collect()
    avg_time_32, total_time_32 = benchmark_keygen_32(quantum_key, kyber_key)
    print(f"    - Average time: {avg_time_32:.2f} µs per operation")
    print(f"    - Total time: {total_time_32:.4f} seconds")

    print("\n[+] Benchmarking 64-byte key generation...")
    print("    - Running garbage collector...")
    gc.collect()
    avg_time_64, total_time_64 = benchmark_keygen_64(quantum_key, kyber_key)
    print(f"    - Average time: {avg_time_64:.2f} µs per operation")
    print(f"    - Total time: {total_time_64:.4f} seconds")

    overall_end = time.perf_counter()
    overall_time = overall_end - overall_start

    print("\n[+] Benchmark Results Summary:")
    print(f"    - 16-byte key: {avg_time_16:.2f} µs per operation")
    print(f"    - 32-byte key: {avg_time_32:.2f} µs per operation")
    print(f"    - 64-byte key: {avg_time_64:.2f} µs per operation")

    print(f"\n[✓] Overall benchmark completed in {overall_time:.4f} seconds")

    key_lengths = ["16 bytes", "32 bytes", "64 bytes"]
    avg_times = [avg_time_16, avg_time_32, avg_time_64]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(key_lengths, avg_times, color='skyblue', width=0.6)

    for bar, time_val in zip(bars, avg_times):
        plt.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.5,
                f'{time_val:.2f} µs', ha='center', va='bottom')
    
    plt.xlabel('Key Length', fontsize=12)
    plt.ylabel('Average Time (µs)', fontsize=12)
    plt.title('Hybrid Key Generation Benchmark', fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()