package merkle_test

import (
	"crypto/sha256"

	"github.com/bobg/merkle/v2"
)

func Example_computeMerkleRoot() {
	var ch <-chan []byte // Represents a sequence of byte strings

	tree := merkle.NewTree(sha256.New())
	for str := range ch {
		tree.Add(str)
	}
	// The Merkle root hash of the sequence of strings is now tree.Root()
}

func Example_produceMerkleProof() {
	var (
		ch  <-chan []byte // Represents a sequence of byte strings
		ref []byte        // Represents the string you will later want to prove is a member of the tree we're about to build
	)

	tree := merkle.NewProofTree(sha256.New(), ref)
	for str := range ch {
		tree.Add(str)
	}
	proof := tree.Proof()
	// A verifier with only the Merkle root hash r,
	// and this proof,
	// can verify ref belongs in the tree by checking:
	//   bytes.Equal(r, proof.Hash(sha256.New(), ref))
	_ = proof
}
