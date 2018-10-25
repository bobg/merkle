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

func (t *unitier) set(str []byte, subtier tier) tier {
	if t == nil {
		u := &unitier{b: str[0]}
		return u.set(str, subtier)
	}
	if t.b == str[0] {
		if len(str) == 1 {
			t.t = subtier
			return t
		}
		if t.t == nil {
			t.t = &unitier{b: str[1]}
		}
		t.t = t.t.set(str[1:], subtier)
		return t
	}
	a := new(arraytier)
	(*a)[t.b] = t.t
	return a.set(str, subtier)
}

func (t *unitier) empty() bool { return false }
