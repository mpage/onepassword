package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mpage/onepassword"
	"golang.org/x/crypto/ssh/terminal"
)

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [flags] [title]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nPrint item details for items with title [title]\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func MustSucceed(action string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s: %s\n", action, err.Error())
		os.Exit(1)
	}
}

func GetPassword() string {
	oldState, err := terminal.MakeRaw(0)
	MustSucceed("Reading password", err)
	defer terminal.Restore(0, oldState)

	term := terminal.NewTerminal(os.Stdin, "")

	pass, err := term.ReadPassword("password: ")
	MustSucceed("Reading password", err)

	return pass
}

func main() {
	flag.Usage = Usage
	var vaultPath = flag.String("vault-path",
		onepassword.DefaultSQLiteVaultConfig.DBPath,
		"Path to the onepassword sqlite database.")
	var profile = flag.String("profile",
		onepassword.DefaultSQLiteVaultConfig.Profile,
		"The onepassword profile that to use.")
	flag.Parse()

	if len(flag.Args()) != 1 {
		Usage()
		os.Exit(1)
	}

	titleRe := flag.Arg(0)
	re, err := onepassword.RegexpMatch(titleRe)
	MustSucceed("compiling regexp", err)

	pass := GetPassword()

	config := onepassword.SQLiteVaultConfig{
		DBPath: *vaultPath,
		Profile: *profile,
	}
	vault, err := onepassword.NewSQLiteVault(pass, &config)
	MustSucceed("opening vault", err)
	defer vault.Close()

	items, err := vault.LookupItems(onepassword.MatchTitle(re))
	MustSucceed("looking up items", err)
	for _, item := range(items) {
		fmt.Printf("%s\n", item.Details)
	}
}
