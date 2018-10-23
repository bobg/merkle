package merkle

type maptier map[byte]tier

func newMaptier() maptier {
	m := make(map[byte]tier)
	return m
}

func (m maptier) get(b byte) tier {
	return m[b]
}

func (m maptier) set(b byte, t tier) {
	m[b] = t
}

func (t maptier) empty() bool {
	return t == nil || len(t) == 0
}
