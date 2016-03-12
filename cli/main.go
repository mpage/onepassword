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
		onepassword.DefaultVaultConfig.DBPath,
		"Path to the onepassword sqlite database.")
	var profile = flag.String("profile",
		onepassword.DefaultVaultConfig.Profile,
		"The onepassword profile that to use.")
	flag.Parse()

	if len(flag.Args()) != 1 {
		Usage()
		os.Exit(1)
	}

	titleRe := flag.Arg(0)
	spf := onepassword.StringPredicateFactory{}
	ipf := onepassword.ItemOverviewPredicateFactory{}
	pred := ipf.Title(spf.Matches(titleRe))

	pass, err := onepassword.ReadPassword("password: ")
	MustSucceed("reading password", err)

	config := onepassword.VaultConfig{
		DBPath: *vaultPath,
		Profile: *profile,
	}
	vault, err := onepassword.NewVault(pass, &config)
	MustSucceed("opening vault", err)
	defer vault.Close()

	items, err := vault.LookupItems(pred)
	MustSucceed("looking up items", err)
	for _, item := range(items) {
		PrintItem(item)
	}
}
