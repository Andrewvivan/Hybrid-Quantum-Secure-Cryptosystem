#include <windows.h>
#include "api.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}

// Explicitly export the functions with their full names
__declspec(dllexport) int pqcrystals_kyber1024_ref_keypair(unsigned char *pk, unsigned char *sk) {
    // Directly call the implementation from the source files
    extern int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
    return crypto_kem_keypair(pk, sk);
}

__declspec(dllexport) int pqcrystals_kyber1024_ref_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    // Directly call the implementation from the source files
    extern int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    return crypto_kem_enc(ct, ss, pk);
}

__declspec(dllexport) int pqcrystals_kyber1024_ref_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    // Directly call the implementation from the source files
    extern int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    return crypto_kem_dec(ss, ct, sk);
}