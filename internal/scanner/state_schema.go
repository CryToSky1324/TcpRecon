package scanner

import (
	"errors"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

const stateSchemaVersion = "1"

var (
	stateMetadataBucket              = []byte("metadata")
	stateSchemaVersionKey            = []byte("schema_version")
	stateCreatedAtKey                = []byte("created_at")
	ErrUnsupportedStateSchemaVersion = errors.New("unsupported state schema version")
	ErrUnversionedStateSchema        = errors.New("unversioned state schema")
	ErrInvalidStateSchemaMetadata    = errors.New("invalid state schema metadata")
)

// InitializeStateSchema creates metadata for a new database or validates the
// schema version and required metadata of an existing database.
func InitializeStateSchema(db *bbolt.DB) error {
	return db.Update(func(tx *bbolt.Tx) error {
		metadata := tx.Bucket(stateMetadataBucket)
		if metadata == nil {
			key, _ := tx.Cursor().First()
			if key != nil {
				return ErrUnversionedStateSchema
			}

			var err error
			metadata, err = tx.CreateBucket(stateMetadataBucket)
			if err != nil {
				return err
			}
			if err := metadata.Put(stateSchemaVersionKey, []byte(stateSchemaVersion)); err != nil {
				return err
			}
			return metadata.Put(
				stateCreatedAtKey,
				[]byte(time.Now().UTC().Format(time.RFC3339Nano)),
			)
		}

		return validateStateSchema(tx)
	})
}

func validateStateSchema(tx *bbolt.Tx) error {
	metadata := tx.Bucket(stateMetadataBucket)
	if metadata == nil {
		return ErrUnversionedStateSchema
	}

	version := metadata.Get(stateSchemaVersionKey)
	if version == nil {
		return ErrUnversionedStateSchema
	}
	if string(version) != stateSchemaVersion {
		return fmt.Errorf(
			"%w: found %q, supported %q",
			ErrUnsupportedStateSchemaVersion,
			version,
			stateSchemaVersion,
		)
	}

	createdAt := metadata.Get(stateCreatedAtKey)
	if _, err := time.Parse(time.RFC3339Nano, string(createdAt)); err != nil {
		return fmt.Errorf("%w: created_at: %v", ErrInvalidStateSchemaMetadata, err)
	}
	return nil
}
