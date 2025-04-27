import os

file_path = "1GB_binary_data.bin"
size_in_gb = 1
chunk_size = 1024 * 1024
total_chunks = (size_in_gb * 1024)

with open(file_path, "wb") as f:
    for _ in range(total_chunks):
        f.write(os.urandom(chunk_size))
