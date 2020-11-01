package merkle

import (
	"bytes"
	"hash"
	"sync"
)

// Tree accepts a sequence of strings via its Add method.
// It builds a merkle hash tree from them.
// After adding all strings in the sequence,
// their merkle root hash may be read via the Root method.
type Tree struct {
	htree *HTree
}

type (
	// ProofStep is one step in a merkle proof.
	ProofStep struct {
		H    []byte
		Left bool
	}

	// Proof is a merkle proof.
	Proof []ProofStep
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
	var lh []byte
	m.htree.withHasher(func(hasher hash.Hash) {
		lh = make([]byte, hasher.Size())
		LeafHash(hasher, lh[:0], str)
	})

	// This must happen outside the call to withHasher to avoid deadlock.
	m.htree.Add(lh)
}

// Root returns the merkle root hash
// for the sequence of strings that have been added to m with Add.
// It is an error to call Add after a call to Root.
func (m *Tree) Root() []byte {
	return m.htree.Root()
}

// Proof returns the merkle proof for the reference string given to NewProofTree.
// It is an error to call Add after a call to Proof.
func (m *Tree) Proof() Proof {
	return m.htree.Proof()
}

// HTree accepts a sequence of leaf hashes via its Add method.
// A leaf hash is the result of calling LeafHash on a string.
// After adding all leaf hashes in the sequence,
// their merkle root hash may be read via the Root method.
//
// Note that a Tree works by converting its input from a sequence of strings
// to the corresponding sequence of leaf hashes and feeding those to an HTree.
type HTree struct {
	ch    chan<- []byte
	ready <-chan struct{}
	root  *[]byte
	proof *Proof

	mu     sync.Mutex // protects hasher
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
	var (
		ch    = make(chan []byte)
		ready = make(chan struct{})
		root  []byte
		proof Proof
		htree = &HTree{
			ch:     ch,
			ready:  ready,
			root:   &root,
			proof:  &proof,
			hasher: hasher,
		}
	)

	go func() {
		defer close(ready)

		var hashes [][]byte

		for h := range ch {

			// Find the lowest height in hashes where this hash fits.
			// For each level where it does not fit,
			// compute a combined hash, empty that level,
			// and continue searching one level higher with the new hash.
			for height := 0; ; height++ {
				if height == len(hashes) {
					// All levels filled. Add a new level.
					hashes = append(hashes, h)
					break
				}
				if hashes[height] == nil {
					// This level is vacant. Fill it.
					hashes[height] = h
					break
				}

				// This level is full. Compute a combined hash and keep searching.
				htree.withHasher(func(hasher hash.Hash) {
					interiorHash(hasher, h[:0], hashes[height], h, &ref, &proof)
				})

				// Also vacate this level.
				hashes[height] = nil
			}
		}

		if len(hashes) == 0 {
			htree.withHasher(func(hasher hash.Hash) {
				hasher.Reset()
				root = hasher.Sum(nil)
			})
			return
		}

		// Combine hashes upward toward the highest level in hashes.
		for _, h := range hashes {
			if h == nil {
				continue
			}
			if root == nil {
				root = h
				continue
			}
			htree.withHasher(func(hasher hash.Hash) {
				interiorHash(hasher, root[:0], h, root, &ref, &proof)
			})
		}
	}()

	return htree
}

// Add adds a leaf hash to the sequence in h.
// The caller must not reuse the space in item.
// It is an error to call Add after a call to Root or Proof.
func (h *HTree) Add(item []byte) {
	h.ch <- item
}

func (h *HTree) withHasher(f func(hasher hash.Hash)) {
	h.mu.Lock()
	f(h.hasher)
	h.mu.Unlock()
}

// Root returns the merkle root hash
// for the sequence of leaf hashes that have been added to h with Add.
// It is an error to call Add after a call to Root.
func (h *HTree) Root() []byte {
	if h.ch != nil {
		close(h.ch)
		h.ch = nil
	}
	<-h.ready
	return *h.root
}

// Proof returns the merkle proof for the reference hash given to NewProofHTree.
// It is an error to call Add after a call to Proof.
func (h *HTree) Proof() Proof {
	if h.ch != nil {
		close(h.ch)
		h.ch = nil
	}
	<-h.ready
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
			*proof = append(*proof, *step)
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

// Hash computes the hash of a merkle proof.
// A valid merkle proof hash matches the root hash of the merkle tree it came from.
//
// To validate a proof made with NewProofTree(..., x)
// (for some byte sequence x)
// it is necessary to call proof.Hash(..., LeafHash(..., ..., x))
//
// To validate a proof made with NewProofHTree(..., x)
// it is only necessary to call proof.Hash(..., x).
func (p Proof) Hash(hasher hash.Hash, ref []byte) []byte {
	result := make([]byte, hasher.Size())
	copy(result, ref)
	for _, step := range p {
		if step.Left {
			interiorHash(hasher, result[:0], step.H, result, nil, nil)
		} else {
			interiorHash(hasher, result[:0], result, step.H, nil, nil)
		}
	}

	return result
}
