package merkle

import "sort"

type (
	slicetier     []slicetierpair
	slicetierpair struct {
		b byte
		t tier
	}
)

func (t *slicetier) finder(b byte) func(int) bool {
	return func(i int) bool {
		return (*t)[i].b >= b
	}
}

func (t *slicetier) get(b byte) tier {
	index := sort.Search(len(*t), t.finder(b))
	if index < len(*t) {
		return (*t)[index].t
	}
	return nil
}

func (t *slicetier) set(b byte, subtier tier) {
	index := sort.Search(len(*t), t.finder(b))
	if index < len(*t) {
		if (*t)[index].b == b {
			(*t)[index].t = subtier
			return
		}
		var (
			before = (*t)[:index]
			after  = (*t)[index:]
		)
		*t = append([]slicetierpair{}, before...)
		*t = append(*t, slicetierpair{b: b, t: subtier})
		*t = append(*t, after...)
		return
	}
}

func (t *slicetier) empty() bool {
	return t == nil || len(*t) == 0
}
