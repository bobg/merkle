package merkle

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestFrontier(t *testing.T) {
	cases := []struct {
		inp  []string
		want Tier
	}{
		{},
		{
			inp: []string{"a"},
			want: Tier{
				'a': newTier(),
			},
		},
		{
			inp: []string{"a", "b"},
			want: Tier{
				'a': newTier(),
				'b': newTier(),
			},
		},
		{
			inp: []string{"a", "ab"},
			want: Tier{
				'a': &Tier{
					'b': newTier(),
				},
			},
		},
		{
			inp: []string{"ab"},
			want: Tier{
				'a': &Tier{
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
			if !f.top.Equal(&c.want) {
				t.Errorf("got:\n%s\nwant:\n%s", spew.Sdump(f.top), spew.Sdump(&c.want))
			}
		})
	}
}
