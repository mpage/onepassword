package onepassword

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os/user"
	"path"

	"github.com/mpage/onepassword/crypto"
	_ "github.com/mattn/go-sqlite3"
)

const (
	DefaultProfile    = "default"
	// Relative to user's home dir
	RelativeVaultPath = "Library/Containers/2BUA8C4S2C.com.agilebits.onepassword-osx-helper/Data/Library/Data/OnePassword.sqlite"
)

// A Vault is a read-only interface to the 1Password SQLite database.
type Vault struct {
	db          *sql.DB
	profileId   int
	masterKP    *crypto.KeyPair    // Encrypts item keypairs
	overviewKP  *crypto.KeyPair    // Encrypts overviews
	categories  map[string]string  // For uuid -> name
}

type VaultConfig struct {
	DBPath  string  // Path to the sqlite file
	Profile string  // Name of 1p profile
}

func resolveDefaultDBPath() string {
	u, err := user.Current()
	if err != nil {
		panic(fmt.Sprintf("Cannot resolve current user: %s", err))
	}

	return path.Join(u.HomeDir, RelativeVaultPath)
}

var DefaultVaultConfig = VaultConfig{
	DBPath: resolveDefaultDBPath(),
	Profile: DefaultProfile,
}

func getCategories(db *sql.DB, profileId int) (map[string]string, error) {
	cats := make(map[string]string)
	err := transact(db, func(tx *sql.Tx) (e error) {
		rows, e := tx.Query(
			"SELECT uuid, singular_name" +
			" FROM categories" +
			" WHERE profile_id = ?",
			profileId)
		if e != nil {
			return
		}
		defer rows.Close()

		// Fill in cats
		for rows.Next() {
			var uuid, name string
			e = rows.Scan(&uuid, &name)
			if e != nil {
				return
			}

			cats[uuid] = name
		}

		return rows.Err()
	})

	if err != nil {
		cats = nil
	}

	return cats, err
}

func NewVault(masterPass string, cfg VaultConfig) (*Vault, error) {
	db, err := sql.Open("sqlite3", cfg.DBPath)
	if err != nil {
		return nil, err
	}

	// Lookup profile
	var profileId, nIters int
	var salt, masterKeyBlob, overviewKeyBlob []byte
	err = transact(db, func(tx *sql.Tx) error {
		row := tx.QueryRow(
			"SELECT id, iterations, master_key_data, overview_key_data, salt" +
			" FROM profiles" +
			" WHERE profile_name = ?",
			cfg.Profile)
		e := row.Scan(&profileId, &nIters, &masterKeyBlob, &overviewKeyBlob, &salt)
		if e == sql.ErrNoRows {
			e = fmt.Errorf("no profile named %q", cfg.Profile)
		}
		return e
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	// Decrypt master/overview keypairs
	derKP := crypto.ComputeDerivedKeys(masterPass, salt, nIters)
	mkp, err := crypto.DecryptMasterKeys(masterKeyBlob, derKP)
	if err != nil {
		db.Close()
		return nil, err
	}
	okp, err := crypto.DecryptMasterKeys(overviewKeyBlob, derKP)
	if err != nil {
		db.Close()
		return nil, err
	}

	// Get category index
	cats, err := getCategories(db, profileId)
	if err != nil {
		db.Close()
		return nil, err
	}

	v := &Vault{
		db: db,
		profileId: profileId,
		masterKP: mkp,
		overviewKP: okp,
		categories: cats,
	}

	return v, nil
}

// An ItemPredicate acts as a query to the 1Password database. It returns true
// if an Item in the database is deemed a match. Otherwise it returns false.
type ItemPredicate func(*Item) bool

// LookupItems finds items in the 1Password database that match the supplied predicate.
func (v *Vault) LookupItems(pred ItemPredicate) ([]Item, error) {
	var items []Item

	err := transact(v.db, func(tx *sql.Tx) (e error) {
		rows, e := tx.Query(
			"SELECT id, category_uuid, key_data, overview_data" +
			" FROM items" +
			" WHERE profile_id = ? AND trashed = 0",
			v.profileId)
		if e != nil {
			return
		}
		defer rows.Close()

		// Figure out matches
		for rows.Next() {
			var itemId int
			var catUuid string
			var itemKeyBlob, opdata []byte
			e = rows.Scan(&itemId, &catUuid, &itemKeyBlob, &opdata)
			if e != nil {
				return
			}

			// Decrypt the overview
			var overview []byte
			overview, e = crypto.DecryptOPData01(opdata, v.overviewKP)
			if e != nil {
				return
			}
			var item Item
			e = json.Unmarshal(overview, &item)
			if e != nil {
				return
			}
			item.Category = Category{catUuid, v.categories[catUuid]}

			// Decrypt the item key
			var kp *crypto.KeyPair
			kp, e = crypto.DecryptItemKey(itemKeyBlob, v.masterKP)
			if e != nil {
				return
			}

			// Decrypt the item details
			detRow := tx.QueryRow(
				"SELECT data FROM item_details" +
				" WHERE item_id = ?", itemId)
			var detailsCT []byte
			e = detRow.Scan(&detailsCT)
			if e != nil {
				return
			}
			var details []byte
			details, e = crypto.DecryptOPData01(detailsCT, kp)
			if e != nil {
				return
			}
			item.Details = details

			if pred(&item) {
				items = append(items, item)
			}
		}

		return rows.Err()
	})

	if err != nil {
		items = nil
	}

	return items, err
}

func (v *Vault) Close() {
	v.db.Close()
}
