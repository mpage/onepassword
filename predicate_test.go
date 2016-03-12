package onepassword

import (
	"testing"
)

func TestStringEquals(t *testing.T) {
	spf := StringPredicateFactory{}
	cases := []struct{
		S1 string
		S2 string
	}{
		{"foo", "bar"},
		{"foo", "Foo"},
		{"foo", "foo"},
	}
	for _, c := range cases {
		expected := c.S1 == c.S2
		if spf.Equals(c.S1)(c.S2) != expected {
			t.Errorf("Equals(%q)(%q) should have returned %v", c.S1, c.S2, expected)
		}
	}
}

func TestStringMatches(t *testing.T) {
	spf := StringPredicateFactory{}
	cases := []struct{
		Regex   string
		S       string
		IsMatch bool
	}{
		{"foo.*", "foobar", true},
		{"^foo$", "foobar", false},
		{"^foo$", "foo", true},
	}
	for _, c := range cases {
		if spf.Matches(c.Regex)(c.S) != c.IsMatch {
			t.Errorf("Matches(%q)(%q) should have returned %v", c.Regex, c.S, c.IsMatch)
		}
	}
}

func TestAnyTag(t *testing.T) {
	tpf := TagPredicateFactory{}
	strs := []string{"foo", "bar"}
	p := func (s string) bool { return s == "foo" }
	if !tpf.Any(p)(strs) {
		t.Errorf("Any should have returned true")
	}

	f := func(s string) bool { return s == "baz" }
	if tpf.Any(f)(strs) {
		t.Errorf("Any should have returned false")
	}
}

func TestAllTags(t *testing.T) {
	tpf := TagPredicateFactory{}
	strs := []string{"foo", "bar"}
	p := func (s string) bool { return s == "foo" || s == "bar" }
	if !tpf.All(p)(strs) {
		t.Errorf("All should have returned true")
	}

	f := func(s string) bool { return s == "foo" }
	if tpf.All(f)(strs) {
		t.Errorf("All should have returned false")
	}
}

func TestTitlePredicate(t *testing.T) {
	ipf := ItemOverviewPredicateFactory{}
	p := func (s string) bool { return s == "foo" }
	io := &ItemOverview{
		Title: "foo",
	}
	if !ipf.Title(p)(io) {
		t.Errorf("Title should have matched")
	}
}

func TestUrlPredicate(t *testing.T) {
	spf := StringPredicateFactory{}
	ipf := ItemOverviewPredicateFactory{}
	io := &ItemOverview{
		Url: "www.foo.com",
	}
	if !ipf.Url(spf.Matches("foo.com"))(io) {
		t.Errorf("Url should have matched")
	}
}

func TestTagsPredicate(t *testing.T) {
	spf := StringPredicateFactory{}
	tpf := TagPredicateFactory{}
	ipf := ItemOverviewPredicateFactory{}
	io := &ItemOverview{
		Tags: []string{"foo", "bar"},
	}
	if !ipf.Tags(tpf.Any(spf.Equals("foo")))(io) {
		t.Errorf("Tags contain foo but predicate didn't match")
	}
}

func TestAndItemOverviewPredicates(t *testing.T) {
	spf := StringPredicateFactory{}
	ipf := ItemOverviewPredicateFactory{}
	io := &ItemOverview{
		Title: "Foo",
		Url: "www.foo.com",
	}

	preds := []ItemOverviewPredicate{
		ipf.Title(spf.Equals("Foo")),
		ipf.Url(spf.Matches("foo.com")),
	}
	if !ipf.And(preds)(io) {
		t.Errorf("Logical and of predicates should have succeeded")
	}

	preds = []ItemOverviewPredicate{
		ipf.Title(spf.Equals("Bar")),
		ipf.Url(spf.Matches("foo.com")),
	}
	if ipf.And(preds)(io) {
		t.Errorf("Logical and of predicates should have failed")
	}
}

func TestOrItemOverviewPredicates(t *testing.T) {
	spf := StringPredicateFactory{}
	ipf := ItemOverviewPredicateFactory{}
	io := &ItemOverview{
		Title: "Foo",
		Url: "www.foo.com",
	}

	preds := []ItemOverviewPredicate{
		ipf.Title(spf.Equals("Bar")),
		ipf.Url(spf.Matches("foo.com")),
	}
	if !ipf.Or(preds)(io) {
		t.Errorf("Logical or of predicates should have succeeded")
	}

	preds = []ItemOverviewPredicate{
		ipf.Title(spf.Equals("Bar")),
		ipf.Url(spf.Matches("zazzle.foo.com")),
	}
	if ipf.Or(preds)(io) {
		t.Errorf("Logical and of predicates should have failed")
	}
}
