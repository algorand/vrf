`python/` contains a (slow, variable-time) Python implementation of the VRF (to generate test vectors and validate the C implementation)
In particular, `debug.py` can be given a (hex-encoded) secret key and will output the (hex-encoded) public key, the VRF proof for "hello", and the corresponding VRF output hash.
The python implementation uses djb's reference python implementation of ed25519, which works with Python 2 only.

`libsodium-wrapper/` contains a `test.go`, a command line tool that wraps our libsodium fork. To build, place your built `libsodium.a` library into `libsodium-wrapper/libs/` and update the hardcoded include path in the `// #cgo CFLAGS: ` line near the top of `test.go`. Alternatively, configure libsodium-fork with `--prefix=/tmp`, install it with `make install`, and then run `test.go` with `LD_LIBRARY_PATH=/tmp/lib`
To use:
	* `go run test.go keygen` will generate a keypair and create two files `vrf.priv` and `vrf.pub` containing the hex-encoded private and public key, respectively.
	* `go run test.go prove "hello"` will use the private key in `vrf.priv` to output a (hex-encoded) proof for the string "hello"
	* `go run test.go verify {hex-encoded proof} "hello"` will use the public key in `vrf.pub` to verify the given (hex-encoded) proof for the string "hello", and if verification succeeds, output the VRF hash
