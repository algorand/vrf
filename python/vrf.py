# Usage:
# use vrf_fullverify and vrf_prove
#
from ed25519 import *

SUITE = chr(0x03) # try-and-increment

def os2ecp(s):
	y = sum(2**i * bit(s,i) for i in range(0,b-1))
	if y >= q:
		raise Exception("point is non-canonically encoded")
	return decodepoint(s)

def ec2osp(P):
	return encodepoint([P[0]%q, P[1]%q])

def validate_pk(pk):
	y = os2ecp(pk)
	y8 = scalarmult(y,8)
	if y8[0] % q == 0 and y8[1] % q == 0:
		raise Exception("public key is a low-order point")
	return y

def decode_proof(pi):
	assert len(pi) == 80
	gamma = os2ecp(pi[0:32])
	c = decodeint(pi[32:48] + 16*chr(0))
	s = decodeint(pi[48:80])
	return (gamma, c, s)

def hash_points(*args):
	hashinput = SUITE + chr(0x02)
	for P_i in args:
		hashinput += ec2osp(P_i)
	c1 = H(hashinput)
	c2 = c1[:16]
	c = decodeint(c2 + 16*chr(0))
	return c

def hash_to_curve_try_and_increment(y, alpha):
	ctr = 0
	pk = ec2osp(y)
	one = chr(0x01)
	h = "invalid"
	while h == "invalid" or (h[0] % q == 0 and h[1] % q == 1):
		CTR = chr((ctr >> 24)%256) + chr((ctr>>16) % 256) + chr((ctr>>8) % 256) + chr(ctr % 256) # big endian
		ctr += 1
		attempted_hash = H(SUITE + one + pk + alpha + CTR)[0:32]
		try:
			h = os2ecp(attempted_hash)
			h = scalarmult(h, 8)
		except:
			h = "invalid"
	return h

def hash_to_curve_elligator2(y, alpha):
	A = 486662
	pk = ec2osp(y)
	one = chr(0x01)
	hash_ = H(SUITE + one + pk + alpha)
	r = hash_[0:32]
	x_0 = (ord(r[31]) >> 7) & 1 # deviating from spec by using the highest bit of r[31] instead of the lowest bit of r[32]
	r_as_int_with_highest_bit_cleared = (decodeint(r) & ((1 << 255) - 1))
	u = (-A * inv(1 + 2*expmod(r_as_int_with_highest_bit_cleared, 2, q))) % q
	v = (u * (u*u + A*u + 1)) % q
	e = expmod(v, (q-1)/2, q)
	finalu = u if e == 1 else (- A - u) % q
	y = ((finalu - 1) * inv(finalu + 1)) % q
	x = xrecover(y)
	if x & 1 != x_0: x = q-x
	h = [x,y]
	assert isoncurve(h)
	h8 = scalarmult(h, 8)
	return h8

def vrf_verify(y, pi, alpha):
	gamma, c, s = decode_proof(pi)
	gs = scalarmult(B,s)
	yc = scalarmult(y,c)
	ycinv = [q-yc[0], yc[1]]
	u = edwards(gs, ycinv)

	#h = hash_to_curve_try_and_increment(y, alpha)
	h = hash_to_curve_elligator2(y, alpha)
	hs = scalarmult(h,s)
	gammac = scalarmult(gamma,c)
	gammacinv = [q-gammac[0], gammac[1]]
	v = edwards(hs, gammacinv)

	cprime = hash_points(h, gamma, u, v)
	return (cprime == c)

def sk_to_privpub(sk):
	h = H(sk)
	a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
	return (a, scalarmult(B,a))

def nonce_generation(sk, h1):
	prefix = H(sk)[32:64]
	r = Hint(prefix + h1) % l
	return r

def vrf_prove(sk, alpha):
	x, y = sk_to_privpub(sk)
	#h = hash_to_curve_try_and_increment(y, alpha)
	h = hash_to_curve_elligator2(y, alpha)
	gamma = scalarmult(h, x)
	k = nonce_generation(sk, ec2osp(h))
	c = hash_points(h, gamma, scalarmult(B,k), scalarmult(h,k))
	s = (k + c * x) % l
	return ec2osp(gamma) + encodeint(c)[0:16] + encodeint(s)

def vrf_proof2hash(pi):
	gamma = decode_proof(pi)[0]
	return H(SUITE + chr(0x03) + ec2osp(scalarmult(gamma, 8)))[0:32]

def vrf_fullverify(pk, pi, alpha):
	y = validate_pk(pk)
	if vrf_verify(y, pi, alpha):
		return vrf_proof2hash(pi)
	else:
		raise Exception("proof is incorrect")
