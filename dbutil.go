package onepassword

import (
	"database/sql"
	"fmt"
)

type transacter func(*sql.Tx) error

// transact exectues the supplied function inside a transaction
func transact(db *sql.DB, fn transacter) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return
	}

	defer func() {
		if p := recover(); p != nil {
			switch p := p.(type) {
			case error:
				err = p
			default:
				err = fmt.Errorf("%s", p)
			}
		}
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	return fn(tx)
}
