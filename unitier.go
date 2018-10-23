package merkle

type unitier struct {
	b byte
	t tier
}

func (t *unitier) get(b byte) tier {
	if t != nil && t.b == b {
		return t.t
	}
	return nil
}

func (t *unitier) set(b []byte, subtier tier) tier {
	if t == nil {
		u := &unitier{b: b[0]}
		return u.set(b, subtier)
	}
	if t.b == b[0] {
		if len(b) == 1 {
			t.t = subtier
			return t
		}
		if t.t == nil {
			t.t = &unitier{b: b[1]}
		}
		t.t = t.t.set(b[1:], subtier)
		return t
	}
	s := &slicetier{slicetierpair{b: t.b, t: t.t}}
	return s.set(b, subtier)
}

func (t *unitier) empty() bool { return false }
