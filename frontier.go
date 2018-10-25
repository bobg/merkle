package merkle

import "hash"

type tier interface {
	get(byte) tier
	set([]byte, tier) tier
	empty() bool
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
	top tier
}

// Exclude adds str to f.
// (It's called Exclude because this means str is excluded from f's complement set.)
func (f *Frontier) Exclude(str []byte) {
	if len(str) == 0 {
		return
	}
	if f.top == nil {
		f.top = &unitier{b: str[0]}
	}
	f.top = f.top.set(str, zerotier{})
}

// MerkleRoot produces the merkle root hash of an in-order, depth-first walk of the frontier.
// This can be used to prove in zero knowledge that a string is not in f's complement set.
func (f *Frontier) MerkleRoot(hasher hash.Hash) []byte {
	m := NewTree(hasher)
	f.Walk(func(str []byte) {
		m.Add(str)
	})
	return m.Root()
}

// Walk performs an in-order depth-first traversal of f,
// calling a callback on each string.
// The callback must make its own copy of the string if needed;
// Walk reuses the space on each callback call.
func (f *Frontier) Walk(fn func(str []byte)) {
	walkHelper(f.top, fn, nil)
}

func walkHelper(tier tier, fn func(str []byte), prefix []byte) {
	if tier == nil {
		return
	}
	for i := 0; i < 256; i++ {
		s := append(prefix, byte(i))
		if subtier := tier.get(byte(i)); subtier != nil {
			walkHelper(subtier, fn, s)
		} else {
			fn(s)
		}
	}
}
