package merkle

import (
	"bytes"
	"hash"
)

// Tree accepts a sequence of strings via its Add method.
// It builds a Merkle hash tree from them.
// After adding all strings in the sequence,
// their Merkle root hash may be read via the Root method.
type Tree struct {
	htree *HTree
}

type (
	// ProofStep is one step in a Merkle proof.
	ProofStep struct {
		H    []byte
		Left bool
	}

	// Proof is a Merkle proof.
	Proof struct {
		Steps []ProofStep

		// This is true for Tree Proofs and false for HTree Proofs.
		// It indicates that the argument to Proof.Hash has to be leaf-hashed first.
		needsLeafHashing bool
	}
)

// NewTree produces a new Tree.
func NewTree(hasher hash.Hash) *Tree {
	return &Tree{htree: NewHTree(hasher)}
}

// NewProofTree produces a new Tree that can compactly prove a given string is in it.
// After adding elements to the tree, call Proof to get the proof.
func NewProofTree(hasher hash.Hash, ref []byte) *Tree {
	return &Tree{htree: NewProofHTree(hasher, LeafHash(hasher, nil, ref))}
}

// Add adds a string to the sequence in m.
// The caller may reuse the space in str.
// It is an error to call Add after a call to Root or Proof.
func (m *Tree) Add(str []byte) {
	hasher := m.htree.hasher
	lh := make([]byte, hasher.Size())
	LeafHash(hasher, lh[:0], str)
	m.htree.Add(lh)
}

// Root returns the Merkle root hash
// for the sequence of strings that have been added to m with Add.
// It is an error to call Add after a call to Root.
func (m *Tree) Root() []byte {
	return m.htree.Root()
}

// Proof returns the Merkle inclusion proof for the reference string given to NewProofTree.
// It is an error to call Add after a call to Proof.
func (m *Tree) Proof() Proof {
	proof := m.htree.Proof()
	proof.needsLeafHashing = true
	return proof
}

// HTree accepts a sequence of leaf hashes via its Add method.
// A leaf hash is the result of calling LeafHash on a string.
// After adding all leaf hashes in the sequence,
// their Merkle root hash may be read via the Root method.
//
// Note that a Tree works by converting its input from a sequence of strings
// to the corresponding sequence of leaf hashes and feeding those to an HTree.
type HTree struct {
	hashes [][]byte
	root   *[]byte
	ref    *[]byte
	proof  *Proof
	hasher hash.Hash
}

// NewHTree produces a new HTree.
func NewHTree(hasher hash.Hash) *HTree {
	return newHTree(hasher, nil)
}

// NewProofHTree produces a new HTree that can compactly prove a given reference hash is in it.
// After adding elements to the tree, call Proof to get the proof.
func NewProofHTree(hasher hash.Hash, ref []byte) *HTree {
	return newHTree(hasher, ref)
}

func newHTree(hasher hash.Hash, ref []byte) *HTree {
	htree := &HTree{hasher: hasher}
	if ref != nil {
		htree.ref = &ref
		htree.proof = new(Proof)
	}
	return htree
}

// Add adds a leaf hash to the sequence in h.
// The caller must not reuse the space in item.
// It is an error to call Add after a call to Root or Proof.
func (h *HTree) Add(item []byte) {
	// Find the lowest height in hashes where this hash fits.
	// For each level where it does not fit,
	// compute a combined hash, empty that level,
	// and continue searching one level higher with the new hash.
	for height := 0; ; height++ {
		if height == len(h.hashes) {
			// All levels filled. Add a new level.
			h.hashes = append(h.hashes, item)
			break
		}
		if h.hashes[height] == nil {
			// This level is vacant. Fill it.
			h.hashes[height] = item
			break
		}

		// This level is full. Compute a combined hash and keep searching.
		interiorHash(h.hasher, item[:0], h.hashes[height], item, h.ref, h.proof)

		// Also vacate this level.
		h.hashes[height] = nil
	}
}

func (h *HTree) finish() {
	if h.root != nil {
		return
	}
	if len(h.hashes) == 0 {
		h.hasher.Reset()
		root := h.hasher.Sum(nil)
		h.root = &root
		return
	}

	// Combine hashes upward toward the highest level in hashes.
	for _, hh := range h.hashes {
		if hh == nil {
			continue
		}
		hh := hh
		if h.root == nil {
			h.root = &hh
			continue
		}
		interiorHash(h.hasher, (*h.root)[:0], hh, *h.root, h.ref, h.proof)
	}
}

// Root returns the Merkle root hash
// for the sequence of leaf hashes that have been added to h with Add.
// It is an error to call Add after a call to Root.
func (h *HTree) Root() []byte {
	h.finish()
	return *h.root
}

// Proof returns the Merkle inclusion proof for the reference hash given to NewProofHTree.
// It is an error to call Add after a call to Proof.
func (h *HTree) Proof() Proof {
	h.finish()
	return *h.proof
}

// LeafHash produces the hash of a leaf of a Tree.
func LeafHash(h hash.Hash, out, in []byte) []byte {
	h.Reset()

	// Domain separator to prevent second-preimage attacks.
	// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
	h.Write([]byte{0})

	h.Write(in)

	return h.Sum(out)
}

// interiorHash produces the hash of an interior node.
func interiorHash(h hash.Hash, out, left, right []byte, ref *[]byte, proof *Proof) {
	lcopy := make([]byte, len(left))
	copy(lcopy, left)
	rcopy := make([]byte, len(right))
	copy(rcopy, right)

	var step *ProofStep
	if ref != nil {
		if bytes.Equal(*ref, left) {
			dup := make([]byte, len(right))
			copy(dup, right)
			step = &ProofStep{H: dup, Left: false}
		} else if bytes.Equal(*ref, right) {
			dup := make([]byte, len(left))
			copy(dup, left)
			step = &ProofStep{H: dup, Left: true}
		}
		if step != nil {
			proof.Steps = append(proof.Steps, *step)
		}
	}

	h.Reset()

	// Domain separator to prevent second-preimage attacks.
	// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
	h.Write([]byte{1})

	h.Write(left)
	h.Write(right)

	out = h.Sum(out)

	if step != nil {
		*ref = out
	}
}

// Hash computes the hash of a Merkle proof.
// A valid Merkle proof hash matches the root hash of the Merkle tree it came from.
//
// To prove that x is in a tree, create a tree t with NewProofTree(h, x).
// Then fill the tree with calls to t.Add.
// Then get the proof p with t.Proof().
// Then check that p.Hash(h, x) is the same as t.Root().
// This will be true only if there was a call t.Add(x) in the proper sequence.
func (p Proof) Hash(hasher hash.Hash, ref []byte) []byte {
	result := make([]byte, hasher.Size())

	if p.needsLeafHashing {
		LeafHash(hasher, result[:0], ref)
	} else {
		copy(result, ref)
	}

	for _, step := range p.Steps {
		if step.Left {
			interiorHash(hasher, result[:0], step.H, result, nil, nil)
		} else {
			interiorHash(hasher, result[:0], result, step.H, nil, nil)
		}
	}

	return result
}
