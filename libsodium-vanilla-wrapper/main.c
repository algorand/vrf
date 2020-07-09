#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "vrf.h"


int readfile(unsigned char *out, int len, const char *name) {
	int fd = 0;
	fd = open(name, O_RDONLY);
	if (fd == -1) {
		return 0;
	}
	ssize_t n = 0, dn = 0;
	do {
		dn = read(fd, out+n, len-n);
		if (dn <= 0) {
			break;
		}
		n += dn;
	} while(n < len);
	close(fd);
	return (n == len && dn >= 0);
}

int main(int argc, char **argv) {
	unsigned char pk[32], skpk[64], alpha[1], pi_good[80], beta[64];
	if (!readfile(pk, 32, "pk")) {
		fprintf(stderr, "pk read error\n");
		return (1);
	}
	if (!readfile(skpk, 32, "sk")) {
		fprintf(stderr, "sk read error\n");
		return (2);
	}
	memmove(skpk+32, pk, 32);
	if (!readfile(alpha, 1, "alpha")) {
		fprintf(stderr, "alpha read error\n");
		return (3);
	}
	if (!readfile(pi_good, 80, "pi")) {
		fprintf(stderr, "pi read error\n");
		return (4);
	}
	if (!readfile(beta, 64, "beta")) {
		fprintf(stderr, "beta read error\n");
		return (5);
	}

	unsigned char pi_ours[80];
	int err = vrf_prove(pi_ours, skpk, alpha, sizeof alpha);
	if (err != 0) {
		fprintf(stderr, "prove() returned error\n");
		return (6);
	}
	if (memcmp(pi_ours, pi_good, 80) != 0) {
		fprintf(stderr, "Produced wrong proof\n");
		return (7);
	}

	unsigned char hash[64];
	err = vrf_verify(hash, pk, pi_ours, alpha, sizeof alpha);
	if (err != 0) {
		fprintf(stderr, "Proof did not verify\n");
		return (8);
	}
	if (memcmp(hash, beta, 64) != 0) {
		fprintf(stderr, "verify() returned wrong hash\n");
		return (9);
	}

	fprintf(stderr, "PASS\n");
	return 0;
}
