package merkle

type zerotier struct{}

func (z zerotier) get(byte) tier {
	return nil
}

func (z zerotier) set(str []byte, subtier tier) tier {
	u := &unitier{b: str[0]}
	return u.set(str, subtier)
}

func (z zerotier) empty() bool {
	return true
}
