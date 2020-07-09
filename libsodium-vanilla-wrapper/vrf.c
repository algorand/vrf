#include <sodium.h>
#include <string.h>
#include "vrf.h"

// ----- vrf_ietfdraft03.h -----
static const unsigned char SUITE = 0x04; /* ECVRF-ED25519-SHA512-Elligator2 */


// ----- convert.c -----

static const unsigned char ONE = 0x01;
static const unsigned char TWO = 0x02;

/* Hash a message to a curve point using Elligator2.
 * Specified in VRF draft spec section 5.4.1.2.
 * The actual elligator2 implementation is ge25519_from_uniform.
 * Runtime depends only on alphalen (the message length)
 * Note: caller is responsible for ensuring Y_point is canonical.
 */
void
hash_to_curve(unsigned char H_string[32],
	const unsigned char Y_point[32],
	const unsigned char *alpha,
	const unsigned long long alphalen)
{
	crypto_hash_sha512_state hs;
	unsigned char            r_string[64];

	/* r = first 32 bytes of SHA512(suite || 0x01 || Y || alpha) */
	crypto_hash_sha512_init(&hs);
	crypto_hash_sha512_update(&hs, &SUITE, 1);
	crypto_hash_sha512_update(&hs, &ONE, 1);
	crypto_hash_sha512_update(&hs, Y_point, 32);
	crypto_hash_sha512_update(&hs, alpha, alphalen);
	crypto_hash_sha512_final(&hs, r_string);

	r_string[31] &= 0x7f; /* clear sign bit */
	crypto_core_ed25519_from_uniform(H_string, r_string); /* elligator2 */
}

/* Subroutine specified in draft spec section 5.4.3.
 * Hashes four points to a 16-byte string.
 * NOTE: Caller must ensure P1, P2, P3, and P4 are already canonical!
 * Constant time. */
void
hash_points(unsigned char c[16], const unsigned char P1[32],
     const unsigned char P2[32], const unsigned char P3[32],
     const unsigned char P4[32])
{
	unsigned char str[2+32*4], c1[64];

	str[0] = SUITE;
	str[1] = TWO;
	memmove(str+2+32*0, P1, 32);
	memmove(str+2+32*1, P2, 32);
	memmove(str+2+32*2, P3, 32);
	memmove(str+2+32*3, P4, 32);
	crypto_hash_sha512(c1, str, sizeof str);
	memmove(c, c1, 16);
	sodium_memzero(c1, 64);
}

/* Decode an 80-byte proof pi into a point gamma, a 16-byte scalar c, and a
 * 32-byte scalar s, as specified in IETF draft section 5.4.4.
 * Returns 0 on success, nonzero on failure.
 * Compare to _vrf_ietfdraft03_decode_proof in libsodium-fork's convert.c
 * Note that this implementation requires gamma to be not just canonical but also on the main subgroup and not of low-order. In theory this could cause us to reject some (unusually constructed) proofs that libsodium-fork would accept.
 */
int
decode_proof(unsigned char Gamma[32], unsigned char c[16],
	unsigned char s[32], const unsigned char pi[80])
{
	if (crypto_core_ed25519_is_valid_point(pi) != 1) {
		return -1;
	}
	memmove(Gamma, pi, 32); /* gamma = pi[0:32] */
	memmove(c, pi+32, 16); /* c = pi[32:48] */
	memmove(s, pi+48, 32); /* s = pi[48:80] */
	return 0;
}



// ----- prove.c -----

/* Utility function to convert a "secret key" (32-byte seed || 32-byte PK)
 * into the public point Y, the private saclar x, and truncated hash of the
 * seed to be used later in nonce generation.
 * Return 0 on success, -1 on failure decoding the public point Y.
 * NOTE: Unlike in libsodium-fork, if the public-key half of skpk is of low
 * order or is not in the main subgroup, this function will return -1.
 * This shouldn't matter in practice -- if users manually corrupt their secret key,
 * that's their own problem.
 */
static int
vrf_expand_sk(unsigned char pk[32], unsigned char x_scalar[32],
	      unsigned char truncated_hashed_sk_string[32], const unsigned char skpk[64])
{
	unsigned char h[64];

	crypto_hash_sha512(h, skpk, 32);
	h[0] &= 248;
	h[31] &= 127;
	h[31] |= 64;
	memmove(x_scalar, h, 32);
	memmove(truncated_hashed_sk_string, h + 32, 32);
	sodium_memzero(h, 64);

	memmove(pk, skpk+32, 32);
	return crypto_core_ed25519_is_valid_point(pk) - 1;
}

/* In libsodium 1.0.18, crypto_core_ed25519_scalar_add leaves secrets on the stack.
 * (in particular, two arrays of size crypto_core_ed25519_NONREDUCEDSCALARBYTES.)
 * Its implementation is copied here but with sodium_memzeros added to clear the secrets.
 */
static void scalar_add_clearsecrets(unsigned char *z, const unsigned char *x, const unsigned char *y) {
	unsigned char x_[crypto_core_ed25519_NONREDUCEDSCALARBYTES];
	unsigned char y_[crypto_core_ed25519_NONREDUCEDSCALARBYTES];

	memset(x_, 0, sizeof x_);
	memset(y_, 0, sizeof y_);
	memcpy(x_, x, crypto_core_ed25519_SCALARBYTES);
	memcpy(y_, y, crypto_core_ed25519_SCALARBYTES);
	sodium_add(x_, y_, crypto_core_ed25519_SCALARBYTES);
	crypto_core_ed25519_scalar_reduce(z, x_);
	sodium_memzero(x_, sizeof x_);
	sodium_memzero(y_, sizeof y_);
}

/* Deterministically generate a (secret) nonce to be used in a proof.
 * Specified in draft spec section 5.4.2.2.
 * Note: In the spec, this subroutine computes truncated_hashed_sk_string
 * Here we instead takes it as an argument, and we compute it in vrf_expand_sk
 */
static void
nonce_generation(unsigned char k_scalar[32],
		     const unsigned char truncated_hashed_sk_string[32],
		     const unsigned char h_string[32])
{
	crypto_hash_sha512_state hs;
	unsigned char			k_string[64];

	/* k_string = SHA512(truncated_hashed_sk_string || h_string) */
	crypto_hash_sha512_init(&hs);
	crypto_hash_sha512_update(&hs, truncated_hashed_sk_string, 32);
	crypto_hash_sha512_update(&hs, h_string, 32);
	crypto_hash_sha512_final(&hs, k_string);

	crypto_core_ed25519_scalar_reduce(k_scalar, k_string); /* k_scalar[0:32] = string_to_int(k_string) mod q */

	sodium_memzero(k_string, sizeof k_string);
}

// Compare to vrf_prove in prove.c
static void prove_helper(unsigned char pi[80], const unsigned char Y_point[32], const unsigned char x_scalar[32], const unsigned char truncated_hashed_sk_string[32], const unsigned char *alpha, const unsigned long long alphalen) {
	unsigned char H_point[32], k_scalar[32], c_scalar[32], cx_scalar[32], Gamma_point[32], kB_point[32], kH_point[32];
	// expand_sk already checked that Y was a valid point
	hash_to_curve(H_point, Y_point, alpha, alphalen);

	crypto_scalarmult_ed25519_noclamp(Gamma_point, x_scalar, H_point); /* Gamma = x*H */
	nonce_generation(k_scalar, truncated_hashed_sk_string, H_point);
	crypto_scalarmult_ed25519_base_noclamp(kB_point, k_scalar); /* compute k*B */
	crypto_scalarmult_ed25519_noclamp(kH_point, k_scalar, H_point); /* compute k*H */
	
	/* c = hash_points(h, gamma, k*B, k*H)
	 * (writes only to first 16 bytes of c_scalar */
	hash_points(c_scalar, H_point, Gamma_point, kB_point, kH_point);
	memset(c_scalar+16, 0, 16); /* zero remaining 16 bytes of c_scalar */

	memmove(pi, Gamma_point, 32); /* pi[0:32] = Gamma */
	memmove(pi+32, c_scalar, 16); /* pi[32:48] = c (16 bytes) */
	
	crypto_core_ed25519_scalar_mul(cx_scalar, c_scalar, x_scalar);
	scalar_add_clearsecrets(pi+48, cx_scalar, k_scalar); /* pi[48:80] = s = c*x + k (mod q) */

	/* k and cx must remain secret */
	sodium_memzero(cx_scalar, sizeof cx_scalar);
	sodium_memzero(k_scalar, sizeof k_scalar);
	/* erase other non-sensitive intermediate state for good measure */
	sodium_memzero(H_point, sizeof H_point);
	sodium_memzero(c_scalar, sizeof c_scalar);
	sodium_memzero(Gamma_point, sizeof Gamma_point);
	sodium_memzero(kB_point, sizeof kB_point);
	sodium_memzero(kH_point, sizeof kH_point);
}

int vrf_prove(unsigned char proof[80], const unsigned char skpk[64], const unsigned char *msg, unsigned long long msglen) {
	unsigned char Y_point[32], x_scalar[32], truncated_hashed_sk_string[32];
	if (vrf_expand_sk(Y_point, x_scalar, truncated_hashed_sk_string, skpk) != 0) {
		sodium_memzero(x_scalar, 32);
		sodium_memzero(truncated_hashed_sk_string, 32);
		sodium_memzero(Y_point, 32); /* for good measure */
		return -1;
	}
	prove_helper(proof, Y_point, x_scalar, truncated_hashed_sk_string, msg, msglen);
	sodium_memzero(x_scalar, 32);
	sodium_memzero(truncated_hashed_sk_string, 32);
	sodium_memzero(Y_point, 32); /* for good measure */
	return 0;
}


// ----- verify.c -----

static const unsigned char THREE = 0x03;

/* Utility function to multiply a point by the cofactor (8) in place
 * NOTE: assumes input is a valid point */
static void multiply_by_cofactor(unsigned char pt[32]) {
	crypto_core_ed25519_add(pt, pt, pt); // pt = 2 * pt_orig
	crypto_core_ed25519_add(pt, pt, pt); // pt = 4 * pt_orig
	crypto_core_ed25519_add(pt, pt, pt); // pt = 8 * pt_orig
}

/* Convert a VRF proof pi into a VRF output hash beta per draft spec section 5.2.
 * This function does not verify the proof! For an untrusted proof, instead call
 * vrf_verify, which will output the hash if verification succeeds.
 * Returns 0 on success, -1 on failure decoding the proof.
 * NOTE: Unlike in the spec, and unlike the libsodium-fork implementation, here we'll reject gamma that's not in the main subgroup or is of low order
 */
int
vrf_proof_to_hash(unsigned char beta[64],
                  const unsigned char pi[80])
{
	unsigned char Gamma_point[32];
	unsigned char hash_input[2+32];

	/* Gamma = pi_string[0:32] */
	memcpy(Gamma_point, pi, 32);
	/* NOTE: Unlike in the spec, and unlike the libsodium-fork implementation, here we'll reject gamma that's not in the main subgroup or is of low order */
	if (!crypto_core_ed25519_is_valid_point(Gamma_point)) {
		return -1;
	}

	/* beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma)) */
	hash_input[0] = SUITE;
	hash_input[1] = THREE;
	multiply_by_cofactor(Gamma_point);
	memcpy(hash_input+2, Gamma_point, 32);
	crypto_hash_sha512(beta, hash_input, sizeof hash_input);

	return 0;
}

/* Validate an untrusted public key as specified in the draft spec section
 * 5.6.1.
 *
 * This means check that it is not of low order and that it is canonically
 * encoded (i.e., y coordinate is already reduced mod p)
 * However, unlike in the spec, and unlike in the libsodium-fork implementation,
 * we _do_  check if the point is on the main subgroup.
 *
 * Returns 0 on success, -1 on failure.
 */
int
vrf_validate_key(const unsigned char pk_string[32])
{
	if (!crypto_core_ed25519_is_valid_point(pk_string)) {
		return -1;
	}
	return 0;
}

/* Verify a proof per draft section 5.3. Return 0 on success, -1 on failure.
 * We assume Y_point has passed public key validation already.
 * Assuming verification succeeds, runtime does not depend on the message alpha
 * (but does depend on its length alphalen)
 * Compare to vrf_verify in libsodium-fork's verify.c
 * This will differ from libsodium-fork in that it rejects proofs where gamma is not on the main subgroup or is of low order whereas libsodium-fork might not.
 */
int
verify_helper(const unsigned char Y_point[32], const unsigned char pi[80],
	   const unsigned char *alpha, const unsigned long long alphalen)
{
	/* Note: c fits in 16 bytes, but ge25519_scalarmult expects a 32-byte scalar.
	 * Similarly, s_scalar fits in 32 bytes but sc25519_reduce takes in 64 bytes. */
	unsigned char c_scalar[32], s_scalar[64], s_scalar_reduced[32], cprime[16];

	//ge25519_p3	 H_point, Gamma_point, U_point, V_point, tmp_p3_point;
	unsigned char H_point[32], Gamma_point[32], U_point[32], V_point[32], tmp_point[32], tmp2_point[32];
	//ge25519_p1p1   tmp_p1p1_point;
	//ge25519_cached tmp_cached_point;

	if (decode_proof(Gamma_point, c_scalar, s_scalar, pi) != 0) {
		return -1;
	}
	/* vrf_decode_proof writes to the first 16 bytes of c_scalar; we zero the
	 * second 16 bytes ourselves, as ge25519_scalarmult expects a 32-byte scalar.
	 */
	memset(c_scalar+16, 0, 16);

	/* vrf_decode_proof sets only the first 32 bytes of s_scalar; we zero the
	 * second 32 bytes ourselves, as sc25519_reduce expects a 64-byte scalar.
	 * Reducing the scalar s mod q ensures the high order bit of s is 0, which
	 * ref10's scalarmult functions require.
	 */
	memset(s_scalar+32, 0, 32);
	crypto_core_ed25519_scalar_reduce(s_scalar_reduced, s_scalar);

	// Y_point is assumed to have already passed public key validation, so we know it's canonical.
	hash_to_curve(H_point, Y_point, alpha, alphalen);

	/* calculate U = s*B - c*Y */
	// TODO: libsodium docs say the functions don't allow c (or s) to be 0 and that they'll return -1 in that case.
	// Figure out whether this is actually true. If so, set tmp_point to the base point ourselves when c is 0 (and likewise for tmp2 when s is 0)
	crypto_scalarmult_ed25519_noclamp(tmp_point, c_scalar, Y_point); /* tmp_point = c*Y */
	crypto_scalarmult_ed25519_base_noclamp(tmp2_point, s_scalar_reduced); /* tmp2_point = s*B */
	crypto_core_ed25519_sub(U_point, tmp2_point, tmp_point); /* U = tmp2_point - tmp_point = s*B - c*Y */

	/* calculate V = s*H -  c*Gamma */
	// TODO: same as above (deal with c and s being 0 if necessary)
	crypto_scalarmult_ed25519_noclamp(tmp_point, c_scalar, Gamma_point); /* tmp_point = c*Gamma */
	crypto_scalarmult_ed25519_noclamp(tmp2_point, s_scalar_reduced, H_point); /* tmp2_point = s*H */
	crypto_core_ed25519_sub(V_point, tmp2_point, tmp_point); /* V = tmp2_point - tmp_point = s*H - c*Gamma */

	hash_points(cprime, H_point, Gamma_point, U_point, V_point);
	return sodium_memcmp(c_scalar, cprime, 16);
}

/* Verify a VRF proof (for a given a public key and message) and validate the
 * public key. If verification succeeds, store the VRF output hash in output[].
 * Specified in draft spec section 5.3.
 * 
 * This will differ from libsodium-fork in that it rejects proofs where gamma is not on the main subgroup or is of low order whereas libsodium-fork might not.
 *
 * For a given public key and message, there are many possible proofs but only
 * one possible output hash.
 *
 * Returns 0 if verification succeeds (and stores output hash in output[]),
 * nonzero on failure.
 */
int
vrf_verify(unsigned char output[64],
	   const unsigned char pk[32],
	   const unsigned char proof[32],
	   const unsigned char *msg, const unsigned long long msglen)
{
	if ((vrf_validate_key(pk) == 0) && (verify_helper(pk, proof, msg, msglen) == 0)) {
		return vrf_proof_to_hash(output, proof);
	} else {
		return -1;
	}
}
