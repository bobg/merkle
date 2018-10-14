package merkle

import (
	"encoding/hex"
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
		m := NewM(sha3.New256)
		for _, inp := range c.input {
			m.Add(inp)
		}
		got := m.Read()
		gotHex := hex.EncodeToString(got)
		if gotHex != c.wantHex {
			t.Errorf("on input %v, got %s, want %s", c.input, gotHex, c.wantHex)
		}
	}
}
