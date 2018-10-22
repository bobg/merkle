package merkle

import "hash"

type ftier map[byte]ftier

func newTier() ftier {
	m := make(map[byte]ftier)
	return m
}

// Frontier is a trie that contains the shortest bytewise prefixes of all strings _not_ in a set.
// See "Zero Knowledge Sets" by Micali, Rabin, Kilian.
//   https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Zero%20Knowledge/Zero-Knowledge_Sets.pdf
//
// Illustration:
// Consider the simplified alphabet a,b,c,d,
// a hypothetical set S of strings in that alphabet,
// and the corresponding frontier set F representing everything not in S,
// such that adding a string to S means also excluding it from F.
// When S is empty, so is F, meaning nothing has been excluded.
// F contains the empty prefix: the prefix of all strings.
// Now we add "a" to S.
// This means removing the empty prefix from F and adding the following:
//   b, c, d, aa, ab, ac, ad
// All strings starting with those prefixes are not in S.
// If we next add "abc" to S,
// we must remove "ab" from F and add:
//   aba, abb, abd, abca, abcb, abcc, abcd
type Frontier struct {
	top ftier
}

func (f *Frontier) Exclude(str []byte) {
	if len(str) == 0 {
		if f.top != nil {
			// xxx error
		}
		return
	}
	if f.top == nil {
		f.top = newTier()
	}
	tier := f.top
	for _, b := range str {
		subtier := tier[b]
		if subtier == nil {
			subtier = newTier()
			tier[b] = subtier
		}
		tier = subtier
	}
	if tier != nil {
		// xxx error?
	}
}

// MerkleRoot produces the merkle root hash of the frontier.
// This can be used to prove in zero knowledge that a string is not in a given set.
func (f *Frontier) MerkleRoot(genHasher func() hash.Hash) [32]byte {
	m := NewTree(genHasher)
	merkleRootHelper(f.top, m, nil)
	return m.Root()
}

func merkleRootHelper(tier ftier, m *Tree, prefix []byte) {
	if tier == nil {
		return
	}
	for i := 0; i < 256; i++ {
		if tier[byte(i)] == nil {
			s := append([]byte{}, prefix...)
			s = append(s, byte(i))
			m.Add(s)
		}
	}
	for i := 0; i < 256; i++ {
		if subtier := tier[byte(i)]; subtier != nil {
			merkleRootHelper(subtier, m, append(prefix, byte(i)))
		}
	}
}

func (t ftier) Equal(other ftier) bool {
	if t == nil {
		return other == nil || len(other) == 0
	}
	if other == nil {
		return len(t) == 0
	}
	for i := 0; i < 256; i++ {
		if !t[byte(i)].Equal(other[byte(i)]) {
			return false
		}
	}
	return true
}
