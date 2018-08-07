package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"encoding/hex"
)

// #cgo CFLAGS: -I/home/adam/src/libsodium-fork/src/libsodium/include
// #cgo LDFLAGS: -L${SRCDIR}/libs -lsodium
// #include <sodium.h>
import "C"

func init(){
	if C.sodium_init() == -1 {
		panic("sodium_init() failed")
	}
}


type (
	VrfProof [80]uint8
	VrfOutput [32]uint8
	VrfPubkey [32]uint8
	VrfPrivkey [64]uint8
)

// Note: Go arrays are copied by value, so any call to VrfProve makes a copy of the secret key that lingers in memory. Do we want to have secret keys live in the C heap and instead pass pointers to them, e.g., allocate a privkey with sodium_malloc and have VrfPrivkey be of type unsafe.Pointer?

func VrfKeygen() (pub VrfPubkey, priv VrfPrivkey) {
	C.crypto_vrf_keygen((*C.uchar)(&pub[0]), (*C.uchar)(&priv[0]))
	return pub, priv
}

func (sk VrfPrivkey) Prove(msg []byte) (proof VrfProof, ok bool) {
	ret := C.crypto_vrf_prove((*C.uchar)(&proof[0]), (*C.uchar)(&sk[0]), (*C.uchar)(&msg[0]), (C.ulonglong)(len(msg)))
	return proof, ret == 1
}

func (proof VrfProof) Hash() (hash VrfOutput, ok bool) {
	ret := C.crypto_vrf_proof2hash((*C.uchar)(&hash[0]), (*C.uchar)(&proof[0]))
	return hash, ret == 1
}

func (pk VrfPubkey) Verify(msg []byte, proof VrfProof) bool {
	ret := C.crypto_vrf_verify((*C.uchar)(&pk[0]), (*C.uchar)(&proof[0]), (*C.uchar)(&msg[0]), (C.ulonglong)(len(msg)))
	return ret == 1
}

func main(){
	if len(os.Args) < 2 {
		fmt.Printf("Usage:\n\t%[1]s keygen\n\t%[1]s prove {msg}\n\t%[1]s verify {proof} {msg}\n", os.Args[0])
		os.Exit(-1)
	}

	switch os.Args[1] {
	case "keygen":
		pub, priv := VrfKeygen()
		if err := ioutil.WriteFile("vrf.priv", []byte(fmt.Sprintf("%x", priv)), 0600); err != nil {
			panic(err)
		}
		if err := ioutil.WriteFile("vrf.pub", []byte(fmt.Sprintf("%x", pub)), 0644); err != nil {
			panic(err)
		}
		fmt.Printf("Wrote keypair to ./vrf.priv and ./vrf.pub\n")
		return
	case "prove":
		var priv VrfPrivkey
		privhex, err := ioutil.ReadFile("vrf.priv")
		if err != nil {
			panic(err)
		}
		n, err := hex.Decode(priv[:], privhex)
		if err != nil || n != len(priv[:]) {
			panic("hex decode of privkey failed")
		}

		proof, ok := priv.Prove([]byte(os.Args[2]))
		if !ok {
			panic("proof failed")
		}
		fmt.Printf("Prove(%s) = %x\n", os.Args[2], proof)
	case "verify":
		var pub VrfPubkey
		pubhex, err := ioutil.ReadFile("vrf.pub")
		if err != nil {
			panic(err)
		}
		n, err := hex.Decode(pub[:], pubhex)
		if err != nil || n != len(pub[:]) {
			panic("hex decode of pubkey failed")
		}

		var proof VrfProof
		n, err = hex.Decode(proof[:], []byte(os.Args[2]))
		if err != nil || n != len(proof) {
			panic("hex decode of proof failed")
		}

		ok := pub.Verify([]byte(os.Args[3]), proof)
		if !ok {
			panic("verify failed")
		}
		fmt.Printf("Verification succeeded\n")
		hash, ok := proof.Hash()
		if !ok {
			panic("proof.Hash failed??")
		}
		fmt.Printf("Output is %x\n", hash)
	default:
		fmt.Printf("Usage:\n\t%[1]s keygen {file}\n\t%[1]s prove {msg}\n\t%[1]s verify {proof} {msg}\n", os.Args[0])
	}
}