package merkle

import "hash"

var (
	leafPrefix     = []byte{0}
	interiorPrefix = []byte{1}
)

type M struct {
	ch     chan []byte
	ready  chan struct{}
	result *[]byte
}

func NewM(genHasher func() hash.Hash) *M {
	var (
		ch     = make(chan []byte)
		ready  = make(chan struct{})
		hasher = genHasher()
		h      = NewH(genHasher)
		result []byte
	)

	go func() {
		defer close(ready)

		for item := range ch {
			hasher.Reset()
			hasher.Write(leafPrefix)
			hasher.Write(item)
			h.Add(hasher.Sum(nil))
		}

		result = h.Read()
	}()

	return &M{
		ch:     ch,
		ready:  ready,
		result: &result,
	}
}

func (m *M) Add(str []byte) {
	m.ch <- str
}

func (m *M) Read() []byte {
	close(m.ch)
	<-m.ready
	return *m.result
}

type H struct {
	ch     chan []byte
	ready  chan struct{}
	result *[]byte
}

func NewH(genHasher func() hash.Hash) *H {
	var (
		ch     = make(chan []byte)
		ready  = make(chan struct{})
		hasher = genHasher()
		roots  [][]byte
		result []byte
	)

	go func() {
		defer close(ready)

		for h := range ch {

			// Find the lowest height in roots where this hash fits.
			// For each level where it does not fit,
			// compute a combined hash, empty that level,
			// and continue searching one level higher with the new hash.
			for height := 0; ; height++ {
				if height == len(roots) {
					// All levels filled. Add a new level.
					roots = append(roots, h)
					break
				}
				if roots[height] == nil {
					// This level is vacant. Fill it.
					roots[height] = h
					break
				}

				// This level is full. Compute a combined hash and keep searching.
				hasher.Reset()
				hasher.Write(interiorPrefix)
				hasher.Write(roots[height])
				hasher.Write(h)
				h = hasher.Sum(nil)

				// Also vacate this level.
				roots[height] = nil
			}
		}

		if len(roots) == 0 {
			hasher.Reset()
			result = hasher.Sum(nil)
			return
		}

		// Combine hashes upward toward the highest level in roots.
		for _, root := range roots {
			if root == nil {
				continue
			}
			if result == nil {
				result = root
				continue
			}
			hasher.Reset()
			hasher.Write(interiorPrefix)
			hasher.Write(root)
			hasher.Write(result)
			result = hasher.Sum(nil)
		}
	}()

	return &H{
		ch:     ch,
		ready:  ready,
		result: &result,
	}
}

func (h *H) Add(item []byte) {
	h.ch <- item
}

func (h *H) Read() []byte {
	close(h.ch)
	<-h.ready
	return *h.result
}
