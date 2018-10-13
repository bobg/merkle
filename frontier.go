package merkle

import (
	"hash"
	"sort"
)

type Tier map[byte]*Tier

func newTier() *Tier {
	m := make(map[byte]*Tier)
	return (*Tier)(&m)
}

type Frontier struct {
	top *Tier
}

func GenFrontier(strs <-chan []byte) *Frontier {
	f := new(Frontier)
	for str := range strs {
		f.Add(str)
	}
	return f
}

func (f *Frontier) Add(str []byte) {
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
		subtier := (*tier)[b]
		if subtier == nil {
			(*tier)[b] = newTier()
			subtier = (*tier)[b]
		}
		tier = subtier
	}
	if tier != nil {
		// xxx error?
	}
}

func (f *Frontier) MerkleRoot(genHasher func() hash.Hash) []byte {
	ch := make(chan []byte)
	go func() {
		merkleRootHelper(f.top, ch, nil)
		close(ch)
	}()
	return MerkleRoot(genHasher, ch)
}

func merkleRootHelper(tier *Tier, ch chan<- []byte, prefix []byte) {
	if tier == nil {
		return
	}
	ch <- prefix
	var keys byteSlice
	for k := range *tier {
		keys = append(keys, k)
	}
	sort.Sort(keys)
	ch <- keys
	for _, k := range keys {
		if subtier := (*tier)[k]; subtier != nil {
			merkleRootHelper(subtier, ch, append(prefix, k))
		}
	}
}

// implements sort.Interface
type byteSlice []byte

func (s byteSlice) Len() int           { return len(s) }
func (s byteSlice) Less(i, j int) bool { return s[i] < s[j] }
func (s byteSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// Contains returns true if the frontier contains the given string, false otherwise.
// It traverses the tiers of the frontier trie.
// If it reaches a leaf before exhausting str, the result is true.
func (f *Frontier) Contains(str []byte) bool {
	tier := f.top
	for _, b := range str {
		if tier == nil {
			return true
		}
		tier = (*tier)[b]
	}
	return false
}

func (t *Tier) Equal(other *Tier) bool {
	if t == nil {
		return other == nil || len(*other) == 0
	}
	if other == nil {
		return len(*t) == 0
	}
	for i := 0; i < 256; i++ {
		if !(*t)[byte(i)].Equal((*other)[byte(i)]) {
			return false
		}
	}
	return true
}
