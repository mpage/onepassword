package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mpage/onepassword"
)

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [flags] [regexp]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nPrint item details for items with title matching [regexp]\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func MustSucceed(action string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s: %s\n", action, err.Error())
		os.Exit(1)
	}
}

func PrintItem(item onepassword.Item) {
	overviewJson, err := json.Marshal(&item.Overview)
	MustSucceed("serializing item", err)
	fmt.Printf("{\"overview\": %s, \"details\": %s}\n", overviewJson, item.Details)
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

	pass, err := onepassword.ReadPassword("password: ")
	MustSucceed("reading password", err)

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
		PrintItem(item)
	}
}
