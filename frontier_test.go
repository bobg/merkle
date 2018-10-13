package merkle

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestFrontier(t *testing.T) {
	cases := []struct {
		inp  []string
		want ftier
	}{
		{},
		{
			inp: []string{"a"},
			want: ftier{
				'a': newTier(),
			},
		},
		{
			inp: []string{"a", "b"},
			want: ftier{
				'a': newTier(),
				'b': newTier(),
			},
		},
		{
			inp: []string{"a", "ab"},
			want: ftier{
				'a': ftier{
					'b': newTier(),
				},
			},
		},
		{
			inp: []string{"ab"},
			want: ftier{
				'a': ftier{
					'b': newTier(),
				},
			},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d", i+1), func(t *testing.T) {
			ch := make(chan []byte)
			go func() {
				for _, s := range c.inp {
					ch <- []byte(s)
				}
				close(ch)
			}()
			f := GenFrontier(ch)
			if !f.top.Equal(c.want) {
				t.Errorf("got:\n%s\nwant:\n%s", spew.Sdump(f.top), spew.Sdump(c.want))
			}
		})
	}
}
