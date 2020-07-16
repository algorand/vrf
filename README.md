`libsodium-vanilla-wrapper/` contains a C implementation of the VRF and a test executable. To build it, just link against vanilla libsodium, e.g. `gcc -lsodium main.c vrf.c`. No libsodium-fork needed!

This code has not been audited yet! Use at your own risk.

This is essentially just the VRF code from libsodium-fork but adapted to use the point / scalar arithmetic functions that libsodium now exports rather than internal libsodium functions. Despite my best efforts, it may have a few subtle differences in behavior from libsodium-fork. In particular, at the moment this implementation will explicitly reject proofs where gamma is not on the main subgroup or is of low order, whereas libsodium-fork will not. (I haven't thought too hard about whether it's possible to make a valid proof where gamma is not on the main subgroup or is of low order; if not then this difference doesn't matter because libsodium-fork would eventually reject the proof anyway.) There may be other differences I missed -- definitely this code should be carefully checked before using it in production. For go-algorand it may be wise to do a protocol-upgrade just in case.

One thing to note: The libsodium docs say that the `crypto_scalarmult_ed25519_noclamp` and `crypto_scalarmult_ed25519_base_noclamp` functions return an error code if passed a 0 scalar. When verifying a proof, we will pass a 0 scalar to these functions if the `c` or `s` in the proof is zero. As of libsodium 1.0.18, it appears that despite returning an error code these functions will give the correct answer (the identity point) so this isn't a problem. However, if this behavior changes in a future version of libsodium, we'll need to handle this case then.

The other directories are from 2018 and not as interesting.

`python/` contains a (slow, variable-time) Python implementation of the VRF (to generate test vectors and validate the C implementation)
In particular, `debug.py` can be given a (hex-encoded) secret key and will output the (hex-encoded) public key, the VRF proof for "hello", and the corresponding VRF output hash.
The python implementation uses djb's reference python implementation of ed25519, which works with Python 2 only.

`libsodium-fork-wrapper/` contains a `test.go`, a command line tool that wraps our libsodium fork. To build, place your built `libsodium.a` library into `libsodium-wrapper/libs/` and update the hardcoded include path in the `// #cgo CFLAGS: ` line near the top of `test.go`. Alternatively, configure libsodium-fork with `--prefix=/tmp`, install it with `make install`, and then run `test.go` with `LD_LIBRARY_PATH=/tmp/lib`
To use:
	* `go run test.go keygen` will generate a keypair and create two files `vrf.priv` and `vrf.pub` containing the hex-encoded private and public key, respectively.
	* `go run test.go prove "hello"` will use the private key in `vrf.priv` to output a (hex-encoded) proof for the string "hello"
	* `go run test.go verify {hex-encoded proof} "hello"` will use the public key in `vrf.pub` to verify the given (hex-encoded) proof for the string "hello", and if verification succeeds, output the VRF hash
