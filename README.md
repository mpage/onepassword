# onepassword

A read-only interface to the Onepassword sqlite database.

# Examples

The following example shows how to query the onepassword database for items
whose title matches the regular expression ```AWS```.

```Go
// Open the vault
vault, err := onepassword.NewSQLiteVault("password", nil)
if err != nil {
       panic(fmt.Sprintf("Failed opening vault: %s", err.Error())
}
defer vault.Close()

// Find items whose title matches "AWS"
re, err := onepassword.RegexpMatch("AWS")
if err != nil {
       panic(fmt.Sprintf("Invalid regexp: %s", err.Error()))
}
query := onepassword.MatchTitle(re)

// Do something with the matches.
items, err := vault.LookupItems(query)
if err != nil {
       panic(fmt.Sprintf("Failed looking up items: %s", err.Error()))
}
for _, item := range(items) {
       fmt.Printf("%s\n", item.Details)
}
```

The cli in ```onepassword/cli``` is a more complete version of the example
above. It will print any items whose title matches a user-supplied regexp to
stdout.
