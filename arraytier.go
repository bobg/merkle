package merkle

type arraytier [256]tier

var emptyArraytier arraytier

func (t *arraytier) get(b byte) tier {
	return t[b]
}

func (t *arraytier) set(b byte, subtier tier) {
	t[b] = subtier
}

func (t *arraytier) empty() bool {
	return t == nil || *t == emptyArraytier
}
