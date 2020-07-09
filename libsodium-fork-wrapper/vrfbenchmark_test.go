package main

import "testing"

// use `go test -bench=.' to run.

var pk VrfPubkey
var sk VrfPrivkey
var proof VrfProof

const msg string = "Hello VRF!"

func BenchmarkKeygen(b *testing.B) {
	for i := 0; i < b.N-1; i++ {
		VrfKeygen()
	}
	// last iteration store pub/sk for other tests
	pub, pri := VrfKeygen()
	pk = pub
	sk = pri
}

func BenchmarkProve(b *testing.B) {

	for i := 0; i < b.N-1; i++ {
		_, ok := sk.Prove([]byte(msg))
		if !ok {
			panic("proof failed")
		}
	}
	pr, ok := sk.Prove([]byte(msg))
	proof = pr
	if !ok {
		panic("proof failed")
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {

		ok, out := pk.Verify([]byte(msg), proof)
		if !ok {
			panic("verify failed")
		}
		_ = out
	}
}

func BenchmarkProof2Hash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hash, ok := proof.Hash()
		if !ok {
			panic("proof2hash failed")
		}
		_ = hash
	}
}
