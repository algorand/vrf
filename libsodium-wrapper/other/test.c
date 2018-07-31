#include "stdlib.h"
#include <sodium.h>


int printhex(unsigned char *x, size_t len) {
	for (size_t i = 0; i < len; i ++) {
		printf("%02x",x[i]);
	}
}

int main(int argc, char **argv){
	if (sodium_init() != 0){
		printf("init failed");
		return -1;
	}

	unsigned char pk[32], sk[32];
	crypto_vrf_keypair(pk, sk);
	printf("pk = ");
	printhex(pk, 32);
	printf("\n");
	printf("sk = ");
	printhex(sk, 32);
	printf("\n");

	unsigned char proof[80];

	unsigned char *msg = "hello";
	printf("msg = ");
	printhex(msg, 5);
	printf("\n");
	crypto_vrf_prove(proof, sk, msg, 5);
	printf("prove(\"hello\") = ");
	printhex(proof, 80);
	printf("\n");

	unsigned char beta[32];
	if (!crypto_vrf_verify(pk, proof, msg, 5)) {
		printf("verify failed\n");
		return -1;
	}
	
	if (!crypto_vrf_proof2hash(beta, proof)){
		printf("proof2hash error\n");
		return -1;
	}
	char beta_out[65];
	for (int j = 0; j < 32; j++){
		printf("%02x",beta[j]);
	}
	printf("\n");
	sodium_bin2hex(beta_out, 65, beta, 32);
	printf("%s\n", beta_out);
	return 0;
}


