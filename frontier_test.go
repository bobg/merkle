package merkle

import (
	"bytes"
	"testing"
)

func TestIsExcluded(t *testing.T) {
	cases := []struct {
		add        []string
		test       string
		wantBool   bool
		wantPrefix string
	}{
		{nil, "abc", true, ""},
		{[]string{"ab"}, "ab", true, "ab"},
		{nil, "abc", true, "ab"},
		{nil, "a", false, ""},
		{nil, "ac", false, ""},
		{nil, "b", false, ""},
		{[]string{"ba"}, "b", false, ""},
		{nil, "ba", true, "ba"},
		{nil, "bac", true, "ba"},
	}

	var f Frontier

	for i, c := range cases {
		for _, a := range c.add {
			f.Exclude([]byte(a))
		}
		gotPrefix, gotBool := f.Check([]byte(c.test))
		if gotBool != c.wantBool {
			t.Errorf("case %d: got %v, want %v", i+1, gotBool, c.wantBool)
			continue
		}
		if gotBool {
			if !bytes.Equal(gotPrefix, []byte(c.wantPrefix)) {
				t.Errorf("case %d: got prefix %s, want %s", i+1, string(gotPrefix), c.wantPrefix)
			}
		}
	}
}
