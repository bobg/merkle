package merkle

type maptier map[byte]tier

func newMaptier() maptier {
	m := make(map[byte]tier)
	return m
}

func (m maptier) get(b byte) tier {
	return m[b]
}

func (m maptier) set(str []byte, subtier tier) tier {
	if len(str) == 1 {
		m[str[0]] = subtier
	} else {
		el := m[str[0]]
		if el == nil {
			el = &unitier{b: str[1]}
		}
		m[str[0]] = el.set(str[1:], subtier)
	}
	return m
}

func (m maptier) empty() bool {
	return m == nil || len(m) == 0
}
