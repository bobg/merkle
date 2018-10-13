package merkle

import (
	"hash"
	"sort"
)

type ftier map[byte]ftier

func newTier() ftier {
	m := make(map[byte]ftier)
	return m
}

// Frontier is a trie that contains the shortest bytewise prefixes of all strings _not_ in a set.
// See "Zero Knowledge Sets" by Micali, Rabin, Kilian.
// (https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Zero%20Knowledge/Zero-Knowledge_Sets.pdf)
//
// Illustration:
// Consider the simplified alphabet a,b,c,d,
// a hypothetical set S of strings in that alphabet,
// and the corresponding frontier set F representing everything not in S,
// such that adding a string to S means also excluding it from F.
// When S is empty, so is F, meaning nothing has been excluded.
// F contains the empty prefix: the prefix of all strings.
// Now we add "a" to S. This means adding the following to F:
//   b, c, d, aa, ab, ac, ad
// All strings starting with those prefixes are not in S.
// If we next add "abc" to S,
// we must remove "ab" from F and add
//   aba, abb, abd, abca, abcb, abcc, abcd
type Frontier struct {
	top ftier
}

// GenFrontier produces the frontier representing all strings _not_ in the input.
func GenFrontier(strs <-chan []byte) *Frontier {
	f := new(Frontier)
	for str := range strs {
		f.exclude(str)
	}
	return f
}

func (f *Frontier) exclude(str []byte) {
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
func (f *Frontier) MerkleRoot(genHasher func() hash.Hash) []byte {
	ch := make(chan []byte)
	go func() {
		merkleRootHelper(f.top, ch, nil)
		close(ch)
	}()
	return MerkleRoot(genHasher, ch)
}

func merkleRootHelper(tier ftier, ch chan<- []byte, prefix []byte) {
	if tier == nil {
		return
	}
	ch <- prefix
	var keys byteSlice
	for k := range tier {
		keys = append(keys, k)
	}
	sort.Sort(keys)
	ch <- keys
	for _, k := range keys {
		if subtier := tier[k]; subtier != nil {
			merkleRootHelper(subtier, ch, append(prefix, k))
		}
	}
}

// implements sort.Interface
type byteSlice []byte

func (s byteSlice) Len() int           { return len(s) }
func (s byteSlice) Less(i, j int) bool { return s[i] < s[j] }
func (s byteSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

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
