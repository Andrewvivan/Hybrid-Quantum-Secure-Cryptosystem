#include <windows.h>
#include "api.h"

// Entry point for the DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}

// Explicitly export the functions with their full names for Kyber768
__declspec(dllexport) int pqcrystals_kyber768_ref_keypair(unsigned char *pk, unsigned char *sk) {
    // Directly call the implementation of the Kyber768 keypair generation function
    extern int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
    return crypto_kem_keypair(pk, sk); // Calling the actual function
}

__declspec(dllexport) int pqcrystals_kyber768_ref_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    // Directly call the implementation of the Kyber768 encapsulation function
    extern int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    return crypto_kem_enc(ct, ss, pk); // Calling the actual function
}

__declspec(dllexport) int pqcrystals_kyber768_ref_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    // Directly call the implementation of the Kyber768 decapsulation function
    extern int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    return crypto_kem_dec(ss, ct, sk); // Calling the actual function
}
