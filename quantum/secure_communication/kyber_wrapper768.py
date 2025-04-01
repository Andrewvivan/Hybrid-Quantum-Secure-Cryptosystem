import ctypes
import os
from pathlib import Path

lib_path = Path(__file__).parent / "libkyber768.dll"
if not os.path.exists(lib_path):
    raise FileNotFoundError("Kyber DLL not found. Run compilation first.")

# Try to load with full path to help with debugging
kyber = ctypes.CDLL(str(lib_path), winmode=0)  # winmode=0 can help with symbol loading

# Define function prototypes
kyber.pqcrystals_kyber768_ref_keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
kyber.pqcrystals_kyber768_ref_keypair.restype = ctypes.c_int

kyber.pqcrystals_kyber768_ref_enc.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
                                              ctypes.POINTER(ctypes.c_ubyte)]
kyber.pqcrystals_kyber768_ref_enc.restype = ctypes.c_int

kyber.pqcrystals_kyber768_ref_dec.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
                                              ctypes.POINTER(ctypes.c_ubyte)]
kyber.pqcrystals_kyber768_ref_dec.restype = ctypes.c_int

def generate_keypair():
    public_key = (ctypes.c_ubyte * 1184)()  
    secret_key = (ctypes.c_ubyte * 2400)() 
    result = kyber.pqcrystals_kyber768_ref_keypair(public_key, secret_key)
    if result != 0:
        raise RuntimeError(f"Key generation failed with error {result}")
    return bytes(public_key), bytes(secret_key)

def encapsulate(public_key):
    ciphertext = (ctypes.c_ubyte * 1088)() 
    shared_secret = (ctypes.c_ubyte * 32)()
    pk = (ctypes.c_ubyte * len(public_key))(*public_key)
    result = kyber.pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, pk)
    if result != 0:
        raise RuntimeError(f"Encapsulation failed with error {result}")
    return bytes(ciphertext), bytes(shared_secret)

def decapsulate(ciphertext, secret_key):
    shared_secret = (ctypes.c_ubyte * 32)()
    ct = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    sk = (ctypes.c_ubyte * len(secret_key))(*secret_key)
    result = kyber.pqcrystals_kyber768_ref_dec(shared_secret, ct, sk)
    if result != 0:
        raise RuntimeError(f"Decapsulation failed with error {result}")
    return bytes(shared_secret)
