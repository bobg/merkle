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
	if index < len(*t) && (*t)[index].b == b {
		return (*t)[index].t
	}
	return nil
}

func (t *slicetier) set(b []byte, subtier tier) tier {
	if t == nil || len(*t) == 0 {
		u := &unitier{b: b[0]}
		return u.set(b, subtier)
	}
	if index := sort.Search(len(*t), t.finder(b[0])); index < len(*t) && (*t)[index].b == b[0] {
		if len(b) == 1 {
			(*t)[index].t = subtier
		} else {
			if (*t)[index].t == nil {
				(*t)[index].t = &unitier{b: b[0]}
			}
			(*t)[index].t = (*t)[index].t.set(b, subtier)
		}
	} else {
		u := &unitier{b: b[0]}
		newtier := u.set(b, subtier)
		*t = append(*t, slicetierpair{b: b[0], t: newtier})
		sort.Slice(*t, func(i, j int) bool { return (*t)[i].b < (*t)[j].b })
	}
	return t
}

func (t *slicetier) empty() bool {
	return t == nil || len(*t) == 0
}
