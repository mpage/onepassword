package onepassword

import 	(
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

// Read a password from stdin
func ReadPassword(prompt string) (string, error) {
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		return "", err
	}
	defer terminal.Restore(0, oldState)
	term := terminal.NewTerminal(os.Stdin, "")
	pass, err := term.ReadPassword(prompt)
	return pass, err
}
