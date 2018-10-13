package merkle

import "hash"

var (
	LeafPrefix     = []byte{0}
	interiorPrefix = []byte{1}
)

// MerkleRoot produces the merkle root hash of a sequence of byte slices.
func MerkleRoot(genHasher func() hash.Hash, items <-chan []byte) []byte {
	hashes := make(chan []byte)

	go func() {
		hasher := genHasher()
		for item := range items {
			hasher.Reset()
			hasher.Write(LeafPrefix)
			hasher.Write(item)
			h := hasher.Sum(nil)
			hashes <- h
		}
		close(hashes)
	}()

	return HashHashes(genHasher, hashes)
}

// HashHashes produces the merkle root hash of a tree of hashes;
// i.e., the leaves are absent but the leaves' hashes are present.
func HashHashes(genHasher func() hash.Hash, hashes <-chan []byte) []byte {
	var (
		hasher = genHasher()
		roots  [][]byte
	)

	for h := range hashes {
		for height := 0; ; height++ {
			if height == len(roots) {
				roots = append(roots, h)
				break
			}
			if roots[height] == nil {
				roots[height] = h
				break
			}
			hasher.Reset()
			hasher.Write(interiorPrefix)
			hasher.Write(roots[height])
			hasher.Write(h)
			h = hasher.Sum(nil)
			roots[height] = nil
		}
	}

	if len(roots) == 0 {
		hasher.Reset()
		return hasher.Sum(nil)
	}

	var res []byte
	for _, root := range roots {
		if root == nil {
			continue
		}
		if res == nil {
			res = root
			continue
		}
		hasher.Reset()
		hasher.Write(interiorPrefix)
		hasher.Write(root)
		hasher.Write(res)
		res = hasher.Sum(nil)
	}

	return res
}
