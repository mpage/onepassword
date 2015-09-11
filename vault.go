package onepassword

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

const (
	DefaultProfile         = "default"
	DefaultSQLiteVaultPath = "/Users/mpage/Library/Containers/2BUA8C4S2C.com.agilebits.onepassword-osx-helper/Data/Library/Data/OnePassword.sqlite"
)

type SQLiteVault struct {
	db          *sql.DB
	masterKP    *KeyPair
	overviewKP  *KeyPair
}

type SQLiteVaultConfig struct {
	DBPath  string
	Profile string
}

func (cfg *SQLiteVaultConfig) Merge(other *SQLiteVaultConfig) (*SQLiteVaultConfig) {
	ret := &SQLiteVaultConfig{}

	if other == nil {
		other = &SQLiteVaultConfig{}
	}

	ret.DBPath = cfg.DBPath
	if other.DBPath != "" {
		cfg.DBPath = other.DBPath
	}

	ret.Profile = cfg.Profile
	if other.Profile != "" {
		cfg.Profile = other.Profile
	}

	return ret
}

var DefaultSQLiteVaultConfig = &SQLiteVaultConfig{
	DBPath: DefaultSQLiteVaultPath,
	Profile: DefaultProfile,
}

func NewSQLiteVault(masterPass string, ucfg *SQLiteVaultConfig) (*SQLiteVault, error) {
	cfg := DefaultSQLiteVaultConfig.Merge(ucfg)
	db, err := sql.Open("sqlite3", cfg.DBPath)
	if err != nil {
		return nil, err
	}

	// Lookup profile
	var nIters int
	var salt, masterKeyBlob, overviewKeyBlob []byte
	err = transact(db, func(tx *sql.Tx) error {
		row := tx.QueryRow(
			"SELECT iterations, master_key_data, overview_key_data, salt" +
			" FROM profiles" +
			" WHERE profile_name = ?",
			cfg.Profile)
		e := row.Scan(&nIters, &masterKeyBlob, &overviewKeyBlob, &salt)
		if e == sql.ErrNoRows {
			e = fmt.Errorf("No profile named '%s'", cfg.Profile)
		}
		return e
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	// Decrypt master/overview keypairs
	derKP := ComputeDerivedKeys(masterPass, salt, nIters)
	mkp, err := DecryptMasterKeys(masterKeyBlob, derKP)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("Failed decoding master key: %s", err.Error())
	}
	okp, err := DecryptMasterKeys(overviewKeyBlob, derKP)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("Failed decoding overview key: %s", err.Error())
	}

	return &SQLiteVault{db, mkp, okp}, nil
}

func (v *SQLiteVault) Close() {
	v.db.Close()
}
