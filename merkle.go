package merkle

import "hash"

// Tree accepts a sequence of strings via its Add method.
// It builds a merkle hash tree from them.
// After adding all strings in the sequence,
// their merkle root hash may be read via the Root method.
type Tree struct {
	ch    chan []byte
	ready chan struct{}
	root  *[32]byte
}

type (
	ProofStep struct {
		H    [32]byte
		Left bool
	}

	Proof []ProofStep
)

var zero32 [32]byte

// NewTree produces a new Tree.
// It uses the hash function produced by genHasher to compute the hashes for the merkle tree nodes.
func NewTree(genHasher func() hash.Hash) *Tree {
	var (
		ch    = make(chan []byte)
		ready = make(chan struct{})
		root  [32]byte
	)

	go func() {
		defer close(ready)

		var (
			hasher = genHasher()
			h      = NewHTree(genHasher)
		)

		for item := range ch {
			h.Add(LeafHash(hasher, item))
		}

		root = h.Root()
	}()

	return &Tree{
		ch:    ch,
		ready: ready,
		root:  &root,
	}
}

// Add adds a string to the sequence in m.
// It is an error to call Add after a call to Root.
func (m *Tree) Add(str []byte) {
	m.ch <- str
}

// Root returns the merkle root hash
// for the sequence of strings that have been added to m with Add.
// It is an error to call Add after a call to Root.
func (m *Tree) Root() [32]byte {
	close(m.ch)
	<-m.ready
	return *m.root
}

// HTree accepts a sequence of leaf hashes via its Add method.
// A leaf hash is the result of calling LeafHash on a string.
// After adding all leaf hashes in the sequence,
// their merkle root hash may be read via the Root method.
//
// Note that a Tree works by converting its input from a sequence of strings
// to the corresponding sequence of leaf hashes and feeding those to an HTree.
type HTree struct {
	ch    chan [32]byte
	ready chan struct{}
	root  *[32]byte
	proof *Proof
}

// NewHTree produces a new HTree.
// It uses the hash function produced by genHasher to compute the hashes for the merkle tree nodes.
func NewHTree(genHasher func() hash.Hash) *HTree {
	return newHTree(genHasher, nil)
}

func newHTree(genHasher func() hash.Hash, ref *[32]byte) *HTree {
	var (
		ch    = make(chan [32]byte)
		ready = make(chan struct{})
		root  [32]byte
		proof Proof
	)

	go func() {
		defer close(ready)

		var (
			hasher = genHasher()
			hashes [][32]byte
		)

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
				if hashes[height] == zero32 {
					// This level is vacant. Fill it.
					hashes[height] = h
					break
				}

				// This level is full. Compute a combined hash and keep searching.
				h = interiorHash(hasher, hashes[height], h, ref, &proof)

				// Also vacate this level.
				hashes[height] = zero32
			}
		}

		if len(hashes) == 0 {
			hasher.Reset()
			hasher.Sum(root[:0])
			return
		}

		// Combine hashes upward toward the highest level in hashes.
		for _, h := range hashes {
			if h == zero32 {
				continue
			}
			if root == zero32 {
				root = h
				continue
			}
			root = interiorHash(hasher, h, root, ref, &proof)
		}
	}()

	return &HTree{
		ch:    ch,
		ready: ready,
		root:  &root,
		proof: &proof,
	}
}

// Add adds a leaf hash to the sequence in h.
// It is an error to call Add after a call to Root.
func (h *HTree) Add(item [32]byte) {
	h.ch <- item
}

// Root returns the merkle root hash
// for the sequence of leaf hashes that have been added to h with Add.
// It is an error to call Add after a call to Root.
func (h *HTree) Root() [32]byte {
	close(h.ch)
	<-h.ready
	return *h.root
}

// LeafHash produces the hash of a leaf of a Tree.
func LeafHash(h hash.Hash, str []byte) [32]byte {
	h.Reset()

	// Domain separator to prevent second-preimage attacks.
	// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
	h.Write([]byte{0})

	h.Write(str)

	var result [32]byte
	h.Sum(result[:0])
	return result
}

// interiorHash produces the hash of an interior node.
func interiorHash(h hash.Hash, left, right [32]byte, ref *[32]byte, proof *Proof) [32]byte {
	if ref != nil {
		if *ref == left {
			*proof = append(*proof, ProofStep{H: right, Left: false})
		} else if *ref == right {
			*proof = append(*proof, ProofStep{H: left, Left: true})
		}
	}

	h.Reset()

	// Domain separator to prevent second-preimage attacks.
	// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
	h.Write([]byte{1})

	h.Write(left[:])
	h.Write(right[:])

	var result [32]byte
	h.Sum(result[:0])
	if ref != nil {
		*ref = result
	}
	return result
}

func (p Proof) Hash(hasher hash.Hash, h [32]byte) [32]byte {
	for _, step := range p {
		if step.Left {
			h = interiorHash(hasher, step.H, h, nil, nil)
		} else {
			h = interiorHash(hasher, h, step.H, nil, nil)
		}
	}
	return h
}
