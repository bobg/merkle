package merkle

import (
	"fmt"
	"testing"
)

func TestIsExcluded(t *testing.T) {
	cases := []struct {
		add  []string
		test string
		want bool
	}{
		{nil, "abc", true},
		{[]string{"ab"}, "ab", true},
		{nil, "abc", true},
		{nil, "a", false},
		{nil, "ac", false},
		{nil, "b", false},
		{[]string{"ba"}, "b", false},
		{nil, "ba", true},
		{nil, "bac", true},
	}

	var f Frontier

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d", i+1), func(t *testing.T) {
			for _, a := range c.add {
				f.Exclude([]byte(a))
			}
			got := f.IsExcluded([]byte(c.test))
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
