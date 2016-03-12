package onepassword

import (
	"regexp"
)

// StringPredicates match strings (shocker!)
type StringPredicate func(string) bool

type StringPredicateFactory struct {
}

func (StringPredicateFactory) Equals(a string) StringPredicate {
	return func(b string) bool {
		return a == b
	}
}

// Matches returns a predicate that returns true if a string matches the
// supplied regexp
func (StringPredicateFactory) Matches(re string) StringPredicate {
	compiled := regexp.MustCompile(re)
	return func(s string) bool {
		return compiled.MatchString(s)
	}
}

// TagPredicate matches lists of strings (tags)
type TagPredicate func([]string) bool

type TagPredicateFactory struct {
}

// Any returns true if the supplied predicate is true for any tag
func (TagPredicateFactory) Any(p StringPredicate) TagPredicate {
	return func(tags []string) bool {
		for _, tag := range tags {
			if p(tag) {
				return true
			}
		}
		return false
	}
}

// All returns true if the supplied predicate is true for all tags
func (TagPredicateFactory) All(p StringPredicate) TagPredicate {
	return func(tags []string) bool {
		for _, tag := range tags {
			if !p(tag) {
				return false
			}
		}
		return true
	}
}

// ItemOverviewPredicates are used to select items from the 1password database
type ItemOverviewPredicate func(*ItemOverview) bool

type ItemOverviewPredicateFactory struct {
}

// Title constructs a predicate that matches against the Title of an ItemOverview
func (ItemOverviewPredicateFactory) Title(p StringPredicate) ItemOverviewPredicate {
	return func(iov *ItemOverview) bool {
		return p(iov.Title)
	}
}

// Url constructs a predicate that matches against the Url of an ItemOverview
func (ItemOverviewPredicateFactory) Url(p StringPredicate) ItemOverviewPredicate {
	return func(iov *ItemOverview) bool {
		return p(iov.Url)
	}
}

// Tags constructs a predicate that matches against the tags of an ItemOverview
func (ItemOverviewPredicateFactory) Tags(p TagPredicate) ItemOverviewPredicate {
	return func(iov *ItemOverview) bool {
		return p(iov.Tags)
	}
}

// And implements logical and over the supplied ItemOverviewPredicates
func (ItemOverviewPredicateFactory) And(ps []ItemOverviewPredicate) ItemOverviewPredicate {
	return func (iov *ItemOverview) bool {
		for _, p := range ps {
			if !p(iov) {
				return false
			}
		}
		return true
	}
}

// Or implements logical or over the supplied ItemOverviewPredicates
func (ItemOverviewPredicateFactory) Or(ps []ItemOverviewPredicate) ItemOverviewPredicate {
	return func (iov *ItemOverview) bool {
		for _, p := range ps {
			if p(iov) {
				return true
			}
		}
		return false
	}
}
