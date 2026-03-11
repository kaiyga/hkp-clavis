package storage

import (
	"context"
	"fmt"
	"hkp-clavis/internal/model"
)

var (
	ErrKeyNotFound = fmt.Errorf("pgp key not found")
)

type StorageRepositotyInterface interface {
	// AddKey handles the insertion or update of PGP keys and their associated UIDs.
	// It performs an UPSERT on pgp_keys and an INSERT (ON CONFLICT DO NOTHING) on pgp_uids.
	// The service layer is responsible for merging UID data before calling this method.
	//
	// Parameters:
	//   ctx: Context for the operation.
	//   keys: A slice of model.PGPKey objects to be added or updated.
	//
	// Returns:
	//   error: An error if the operation fails, wrapped with context (e.g., database connection issues, SQL execution errors).
	AddKey(ctx context.Context, keys []*model.PGPKey) error

	// VerifyUID updates the verification status of a specific User ID (UID) based on a token.
	// It checks the token's validity and expiry before setting 'verified' to true and clearing token fields.
	//
	// Parameters:
	//   ctx: Context for the operation.
	//   fingerprint: The fingerprint of the PGP key.
	//   email: The email address associated with the UID to verify.
	//   token: The verification token provided by the user.
	//
	// Returns:
	//   error: Returns an error if:
	//     - No matching UID entry is found (e.g., wrong fingerprint or email).
	//     - The UID is already verified.
	//     - The provided token does not match the stored token.
	//     - The token has expired.
	//     - Database operation fails (e.g., connection issues, SQL update errors).
	//     Specific errors like "invalid verification token or link" are used for security reasons.
	VerifyUID(ctx context.Context, fingerprint, email, token string) error

	// GetKey retrieves a PGP key and its associated UIDs by fingerprint.
	// It only includes UIDs that are marked as 'verified = true' in the database.
	//
	// Parameters:
	//   ctx: Context for the operation.
	//   fingerprint: The fingerprint of the PGP key to retrieve.
	//
	// Returns:
	//   []*model.PGPKey: A slice containing the retrieved PGP key (or an empty slice if not found).
	//   error: Returns an error if:
	//     - The key is not found (errors.Is(err, ErrKeyNotFound)).
	//     - Database query or scanning fails.
	GetKey(ctx context.Context, fingerprint string) ([]*model.PGPKey, error)

	// Index searches for PGP keys based on a query string.
	// It matches against UID strings and emails using case-insensitive regular expressions.
	// Only keys with at least one verified UID matching the search will be returned.
	//
	// Parameters:
	//   ctx: Context for the operation.
	//   q: The query string (treated as a case-insensitive regular expression).
	//
	// Returns:
	//   []*model.PGPKey: A slice of matching PGPKey objects, each containing only their verified UIDs.
	//   error: Returns an error if database query or scanning fails.
	Index(ctx context.Context, q string) ([]*model.PGPKey, error)
	// CleanupStaleKeys identifies and deletes PGP keys that no longer have any associated UIDs.
	// This method is intended to be run periodically, e.g., by a cron job.
	//
	// Parameters:
	//   ctx: Context for the operation.
	//
	// Returns:
	//   int: The number of keys deleted.
	//   error: An error if the cleanup operation fails.
	CleanupStaleKeys(ctx context.Context) (int, error)
}
