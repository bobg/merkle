package merkle

type arraytier [256]tier

var emptyArraytier arraytier

func (t *arraytier) get(b byte) tier {
	return t[b]
}

func (t *arraytier) set(str []byte, subtier tier) tier {
	if len(str) == 1 {
		(*t)[str[0]] = subtier
	} else {
		el := (*t)[str[0]]
		if el == nil {
			el = &unitier{b: str[1]}
		}
		(*t)[str[0]] = el.set(str[1:], subtier)
	}
	return t
}

func (t *arraytier) empty() bool {
	return t == nil || *t == emptyArraytier
}
