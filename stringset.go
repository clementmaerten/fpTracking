package fpTracking

type StringSet struct {
	set map[string]bool
}

func NewStringSet() *StringSet {
	return &StringSet{make(map[string]bool)}
}

func (set *StringSet) Add(s string) bool {
	_, found := set.set[s]
	set.set[s] = true
	return !found	//False if it existed already
}

func (set *StringSet) Get(s string) bool {
	_, found := set.set[s]
	return found	//true if it existed already
}

func (set *StringSet) Remove(s string) {
	delete(set.set, s)
}

func (set *StringSet) GetSet() map[string]bool {
	return set.set
}

func (set *StringSet) Length() int {
	return len(set.set)
}