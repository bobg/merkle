package merkle_test

import (
	"crypto/sha256"

	"github.com/bobg/merkle/v2"
)

func ExampleComputeMerkleRoot() {
	var ch <-chan []byte // Represents a sequence of byte strings

	tree := merkle.NewTree(sha256.New())
	for str := range ch {
		tree.Add(str)
	}
	// The merkle root hash of the sequence of strings is now tree.Root()
}

func ExampleProduceMerkleProof() {
	var (
		ch  <-chan []byte // Represents a sequence of byte strings
		ref []byte        // Represents the string you will later want to prove is a member of the tree we're about to build
	)

	tree := merkle.NewProofTree(sha256.New(), ref)
	for str := range ch {
		tree.Add(str)
	}
	proof := tree.Proof()
	// A verifier with only the merkle root hash r,
	// and this proof,
	// can verify ref belongs in the tree by checking:
	//   bytes.Equal(proof.Hash(sha256.New(), ref), r)
	_ = proof
}
