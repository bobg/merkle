package merkle

import (
	"sort"
)

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

func (t *slicetier) set(str []byte, subtier tier) tier {
	if t == nil || len(*t) == 0 {
		u := &unitier{b: str[0]}
		return u.set(str, subtier)
	}
	if index := sort.Search(len(*t), t.finder(str[0])); index < len(*t) && (*t)[index].b == str[0] {
		if len(str) == 1 {
			(*t)[index].t = subtier
		} else {
			if (*t)[index].t == nil {
				(*t)[index].t = &unitier{b: str[1]}
			}
			(*t)[index].t = (*t)[index].t.set(str[1:], subtier)
		}
	} else {
		if len(str) == 1 {
			*t = append(*t, slicetierpair{b: str[0], t: subtier})
		} else {
			u := &unitier{b: str[1]}
			newtier := u.set(str[1:], subtier)
			*t = append(*t, slicetierpair{b: str[0], t: newtier})
		}
		sort.Slice(*t, func(i, j int) bool { return (*t)[i].b < (*t)[j].b })
	}
	return t
}

func (t *slicetier) empty() bool {
	return t == nil || len(*t) == 0
}
