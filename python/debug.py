import vrf
import sys
if len(sys.argv) < 2:
	print("Usage: %s {hex-encoded sk}" % sys.argv[0])
	exit(1)
sk = sys.argv[1].decode('hex')
pk = vrf.publickey(sk)
print("pk = %s" % pk.encode('hex'))
print("sk = %s" % sk.encode('hex'))
proof = vrf.vrf_prove(sk, "hello")
print("prove(%s) = %s" % ("hello".encode('hex'), proof.encode('hex')))
print("verify:")
y = vrf.validate_pk(pk)
print(vrf.vrf_fullverify(pk, proof, "hello").encode('hex'))
