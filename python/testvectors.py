#!/usr/bin/env python2
# Generate some VRF test vectors of the form:
# {seed, pk, proof, hash, msg}

import vrf
import os

def make_testvector(msglen):
	sk = os.urandom(32)
	msg = os.urandom(msglen)
	#_, pk = vrf.sk_to_privpub(sk)
	pk = vrf.publickey(sk)
	proof = vrf.vrf_prove(sk, msg)
	hash = vrf.vrf_fullverify(pk, proof, msg)
	return (sk, pk, proof, hash, msg)

# format a test vector as C source to be included in a test
def format_testvector(sk, pk, proof, hash, msg):
	tobytearray = lambda s : '{' + ','.join('0x%02x' % ord(c) for c in s) + '}'
	tobytestring = lambda s : '"' + ''.join('\\x%02x' % ord(c) for c in s) + '"'
	return "{%s,%s,%s,%s,%s}" % (tobytearray(sk), tobytearray(pk), tobytearray(proof), tobytearray(hash), tobytestring(msg))

if __name__ == '__main__':
	for i in range(10):
		print(format_testvector(*make_testvector(i)) + ",")
