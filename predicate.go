package onepassword

import (
	"regexp"
)

// A StringPredicate matches a string. These are used against individual fields
// (e.g. Title, Url) and individual tags of an Item.
type StringPredicate func(string) bool

// SPFactory constructs StringPredicates
type SPFactory struct {
}

// Equals constructs a predicate that tests string equality with str.
func (SPFactory) Equals(str string) StringPredicate {
	return func(b string) bool {
		return str == b
	}
}

// Matches constructs a predicate that tests regular expression matching using
// regex.
func (SPFactory) Matches(regex string) StringPredicate {
	compiled := regexp.MustCompile(regex)
	return func(s string) bool {
		return compiled.MatchString(s)
	}
}

// A TagPredicate matches against item tags.
type TagPredicate func([]string) bool

// TPFactory constructs TagPredicates
type TPFactory struct {
}

// Any constructs a higher order predicate that returns true if pred is true
// for any tag.
func (TPFactory) Any(pred StringPredicate) TagPredicate {
	return func(tags []string) bool {
		for _, tag := range tags {
			if pred(tag) {
				return true
			}
		}
		return false
	}
}

// All constructs a higher order predicate that returns true if pred is true
// for all tags.
func (TPFactory) All(pred StringPredicate) TagPredicate {
	return func(tags []string) bool {
		for _, tag := range tags {
			if !pred(tag) {
				return false
			}
		}
		return true
	}
}

// An ItemOverviewPredicate acts as a query to the 1Password database. It is
// used by Vault.LookupItems to find items in the database.
type ItemOverviewPredicate func(*ItemOverview) bool

// IOPFactory constructs ItemOverviewPredicates
type IOPFactory struct {
}

// Title constructs a higher order predicate that applies pred to the Title
// field of an ItemOverview.
func (IOPFactory) Title(pred StringPredicate) ItemOverviewPredicate {
	return func(iov *ItemOverview) bool {
		return pred(iov.Title)
	}
}

// Url constructs a higher order predicate that applies pred to the Url field
// of an ItemOverview.
func (IOPFactory) Url(pred StringPredicate) ItemOverviewPredicate {
	return func(iov *ItemOverview) bool {
		return pred(iov.Url)
	}
}

// Tags constructs a higher order predicate that applies pred to the Tags field
// of an ItemOverview.
func (IOPFactory) Tags(pred TagPredicate) ItemOverviewPredicate {
	return func(iov *ItemOverview) bool {
		return pred(iov.Tags)
	}
}

// And constructs a higher order predicate that performs logical and of preds.
func (IOPFactory) And(preds []ItemOverviewPredicate) ItemOverviewPredicate {
	return func (iov *ItemOverview) bool {
		for _, p := range preds {
			if !p(iov) {
				return false
			}
		}
		return true
	}
}

// And constructs a higher order predicate that performs logical or of preds.
func (IOPFactory) Or(preds []ItemOverviewPredicate) ItemOverviewPredicate {
	return func (iov *ItemOverview) bool {
		for _, p := range preds {
			if p(iov) {
				return true
			}
		}
		return false
	}
}
