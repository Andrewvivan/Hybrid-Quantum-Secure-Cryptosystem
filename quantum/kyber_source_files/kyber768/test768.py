from kyber_wrapper768 import generate_keypair, encapsulate, decapsulate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import binascii

def encrypt_message(shared_secret, message):
    key = shared_secret[:16]  # Use first 16 bytes as AES key
    iv = os.urandom(16)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + encrypted_message  # Prepend IV to ciphertext

def decrypt_message(shared_secret, encrypted_message):
    key = shared_secret[:16]
    iv = encrypted_message[:16]  # Extract IV
    ciphertext = encrypted_message[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def main():
    try:
        # Generate keypair using Kyber 768
        public_key, secret_key = generate_keypair()
        print("\n")
        print("-------Generated keypair using Kyber 768-------")
        print(f"Public key length: {len(public_key)} bytes")
        print(f"Secret key length: {len(secret_key)} bytes")
        print("\n")
        print(f"Public Key (hex): {binascii.hexlify(public_key).decode()}")
        print("\n")
        print(f"Secret Key (hex): {binascii.hexlify(secret_key).decode()}")

        # Perform encapsulation using Kyber 768
        ciphertext, shared_secret_1 = encapsulate(public_key)
        print("\n")
        print("\nPerformed encapsulation")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print("\n")
        print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
        print("\n")
        print(f"Shared secret (hex): {binascii.hexlify(shared_secret_1).decode()}")
        print("\n")

        # Perform decapsulation using Kyber 768
        shared_secret_2 = decapsulate(ciphertext, secret_key)
        print("\nPerformed decapsulation")
        print("Shared secrets match:", shared_secret_1 == shared_secret_2)
        print("\n")

        # Get user message
        message = input("\nEnter a message to encrypt: ")
        print("\n")

        # Encrypt message
        encrypted_message = encrypt_message(shared_secret_1, message)
        print(f"Encrypted message (hex): {binascii.hexlify(encrypted_message).decode()}")

        # Decrypt message
        decrypted_message = decrypt_message(shared_secret_2, encrypted_message)
        print(f"Decrypted message: {decrypted_message}")
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
