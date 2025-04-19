import time
import gc
import re
import matplotlib.pyplot as plt
from argon2.low_level import hash_secret_raw, Type

def is_valid_binary(s):
    return all(c in '01' for c in s)

def is_valid_hex_32byte(s):
    return bool(re.fullmatch(r'[0-9a-fA-F]{64}', s))

def generate_hybrid_key(quantum_key, kyber_key, hash_len):
    combined = (quantum_key + kyber_key).encode('utf-8')
    salt = bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2")
    return hash_secret_raw(
        secret=combined,
        salt=salt,
        time_cost=3,
        memory_cost=102400,
        parallelism=8,
        hash_len=hash_len,
        type=Type.ID
    )

def benchmark_keygen(quantum_key, kyber_key, hash_len, iterations=100, warmups=10):
    for _ in range(warmups):
        generate_hybrid_key(quantum_key, kyber_key, hash_len)

    gc.collect()
    gc.disable()

    total_start = time.perf_counter()
    start = total_start

    for _ in range(iterations):
        generate_hybrid_key(quantum_key, kyber_key, hash_len)

    end = time.perf_counter()

    gc.enable()
    gc.collect()

    avg_time_micro = ((end - start) / iterations) * 1e6
    total_time_seconds = end - total_start

    return avg_time_micro, total_time_seconds

def main():
    quantum_key = "10110101001010101101010100101010110101010010101011010101001010101101010100101010"
    kyber_key = "7f8a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f7a8b9c6d5e4f3a2b1c0d7e8f9a"

    if not is_valid_binary(quantum_key):
        print("Error: Hardcoded quantum key is invalid. It must only contain 0s and 1s.")
        return

    if not is_valid_hex_32byte(kyber_key):
        print("Error: Hardcoded Kyber key is invalid. It must be a valid 32-byte (64 hex characters) string.")
        return

    print("[+] Completing hybrid key generation benchmark. Please wait....")

    overall_start = time.perf_counter()

    results = []
    test_lengths = [16, 32, 64]
    total_tests = len(test_lengths)

    for idx, length in enumerate(test_lengths, 1):
        result = benchmark_keygen(quantum_key, kyber_key, hash_len=length)
        results.append((length, result))

    overall_end = time.perf_counter()
    overall_time = overall_end - overall_start

    print("\n[+] Benchmark Results Summary:")
    for length, (avg_time, total_time) in results:
        print(f"    - {length}-byte key: {avg_time:.2f} µs per operation")

    print(f"\n[✓] Overall benchmark completed in {overall_time:.4f} seconds")

    # Plotting the results
    lengths = [length for length, _ in results]
    avg_times = [avg for _, (avg, _) in results]

    plt.figure(figsize=(8, 5))
    plt.bar([str(l) + " bytes" for l in lengths], avg_times, color='skyblue')
    plt.xlabel('Key Length')
    plt.ylabel('Average Time (µs)')
    plt.title('Hybrid Key Generation Benchmark')
    plt.tight_layout()
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.show()

if __name__ == "__main__":
    main()
