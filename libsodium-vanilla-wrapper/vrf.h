// See vrf.c for documentation
int vrf_prove(unsigned char proof[80], const unsigned char skpk[64], const unsigned char *msg, unsigned long long msglen);
int vrf_verify(unsigned char output[64], const unsigned char pk[32], const unsigned char proof[80], const unsigned char *msg, unsigned long long msglen);

int vrf_proof_to_hash(unsigned char hash[64], const unsigned char proof[80]); // Doesn't verify the proof; always use vrf_verify instead (unless the proof is one you just created yourself with vrf_prove)
