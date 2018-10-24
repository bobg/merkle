package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestMerkleRoot(t *testing.T) {
	cases := []struct {
		input   [][]byte
		wantHex string
	}{
		{nil, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
		{[][]byte{{1}}, "76ab70dc46775b641a8e71507b07145aed11ae5efc0baa94ac06876af2b3bf5c"},
		{[][]byte{{1}, {2}}, "1dad5e07e988e0e446e2cce0b77d2ea44a1801efea272d2e2bc374037a5bc1a8"},
		{[][]byte{{1}, {2}, {3}}, "4f554b3aea550c2f7a86917c8c02a0ee842a813fadec1f4c87569cff27bccd14"},
		{[][]byte{{1}, {2}, {3}, {4}}, "c39898712f54df7e2ace99e3829c100c1aaff45c65312a674ba9e24b37c46bf4"},
		{[][]byte{{1}, {2}, {3}, {4}, {5}}, "49b61513bcc94c883a410c372f7dfa93456aed3c3c23223b0e5962bc44954c92"},
		{[][]byte{{1}, {2}, {3}, {4}, {5}, {6}}, "61811c47bfd7e41e52cd7421ec9b4d39ceac28fabdfc6a45f74eb36e173fd1b2"},
		{[][]byte{{1}, {2}, {3}, {4}, {5}, {6}, {7}}, "dd2545905846f83c3265ca731c2789235f349ac2c3a2b3ab07fcd3cffb498b0d"},
	}

	for _, c := range cases {
		m := NewTree(sha3.New256())
		for _, inp := range c.input {
			m.Add(inp)
		}
		got := m.Root()
		gotHex := hex.EncodeToString(got[:])
		if gotHex != c.wantHex {
			t.Errorf("on input %v, got %s, want %s", c.input, gotHex, c.wantHex)
		}
	}
}

func TestText(t *testing.T) {
	f, err := os.Open("testdata/udhr.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const chunksize = 256

	tree := NewTree(sha256.New())
	hasher := sha256.New()
	var frontier Frontier

	for {
		var buf [chunksize]byte
		n, err := io.ReadFull(f, buf[:])
		if err == io.EOF {
			// "The error is EOF only if no bytes were read."
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			t.Fatal(err)
		}
		tree.Add(buf[:n])
		var leafhash [32]byte
		LeafHash(hasher, leafhash[:0], buf[:n])
		frontier.Exclude(leafhash[:])
	}

	const treeWantHex = "8acc3ef309961457bde157842e2a9d7b403294c30172b497372c19acecc622e5"
	treeRoot := tree.Root()
	treeRootHex := hex.EncodeToString(treeRoot[:])
	if treeRootHex != treeWantHex {
		t.Errorf("merkle tree: got %s, want %s", treeRootHex, treeWantHex)
	}

	const frontierWantHex = "1636797e538ff92e187c9028d648bdf0d13acc9196953960022de3382fb53cae"
	frontierRoot := frontier.MerkleRoot(sha256.New())
	frontierRootHex := hex.EncodeToString(frontierRoot[:])
	if frontierRootHex != frontierWantHex {
		t.Errorf("frontier: got %s, want %s", frontierRootHex, frontierWantHex)
	}
}

func BenchmarkTextMerkleTree(b *testing.B) {
	for i := 0; i < b.N; i++ {
		func() {
			f, err := os.Open("testdata/udhr.txt")
			if err != nil {
				b.Fatal(err)
			}
			defer f.Close()

			const chunksize = 256
			tree := NewTree(sha256.New())
			for {
				var buf [chunksize]byte
				n, err := io.ReadFull(f, buf[:])
				if err == io.EOF {
					// "The error is EOF only if no bytes were read."
					break
				}
				if err != nil && err != io.ErrUnexpectedEOF {
					b.Fatal(err)
				}
				tree.Add(buf[:n])
			}
			tree.Root()
		}()
	}
}

// Note: experimenting with different implementations of Frontier
// tiers produced the following benchmark results:
//   - when tiers are map[byte]*tier
//     BenchmarkTextFrontier takes 1,425,624 ns/op
//     BenchmarkTextFrontierMerkleRoot takes 4,513,747,117 ns/op
//   - when tiers are [256]*tier
//     BenchmarkTextFrontier takes 10,330,605 ns/op
//     BenchmarkTextFrontierMerkleRoot takes 4,358,089,679 ns/op
//   - when tiers are zerotiers, unitiers, and slicetiers
//     BenchmarkTextFrontier takes 443,292 ns/op (!!)
//     BenchmarkTextFrontierMerkleRoot takes 4,593,492,209 ns/op
func BenchmarkTextFrontier(b *testing.B) {
	for i := 0; i < b.N; i++ {
		func() {
			f, err := os.Open("testdata/udhr.txt")
			if err != nil {
				b.Fatal(err)
			}
			defer f.Close()

			const chunksize = 256
			var frontier Frontier
			for {
				var buf [chunksize]byte
				n, err := io.ReadFull(f, buf[:])
				if err == io.EOF {
					// "The error is EOF only if no bytes were read."
					break
				}
				if err != nil && err != io.ErrUnexpectedEOF {
					b.Fatal(err)
				}
				frontier.Exclude(buf[:n])
			}
		}()
	}
}

func BenchmarkTextFrontierMerkleRoot(b *testing.B) {
	for i := 0; i < b.N; i++ {
		func() {
			f, err := os.Open("testdata/udhr.txt")
			if err != nil {
				b.Fatal(err)
			}
			defer f.Close()

			const chunksize = 256
			var frontier Frontier
			for {
				var buf [chunksize]byte
				n, err := io.ReadFull(f, buf[:])
				if err == io.EOF {
					// "The error is EOF only if no bytes were read."
					break
				}
				if err != nil && err != io.ErrUnexpectedEOF {
					b.Fatal(err)
				}
				frontier.Exclude(buf[:n])
			}
			frontier.MerkleRoot(sha256.New())
		}()
	}
}
