package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	repo "gadrid/internal/repo/storage"
	service "gadrid/internal/service/storage"
	"strings"
	"time"

	_ "embed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed structure.sql
var db_struct string

type PostgresqlStorageRepo struct {
	poll *pgxpool.Pool
}

// Get context, url
// Return postgresql repository
func New(ctx context.Context, pool *pgxpool.Pool) repo.StorageRepositotyInterface {
	_, err := pool.Exec(ctx, db_struct)
	if err != nil {
		panic(err)
	}

	return PostgresqlStorageRepo{
		poll: pool,
	}
}

func (s PostgresqlStorageRepo) AddKey(ctx context.Context, keys []*service.PGPkey) error {
	tx, err := s.poll.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error postgresql: AddKey: begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, k := range keys {
		fingerprint := k.Fingerprint
		// Upsert pgp_keys
		_, err = tx.Exec(ctx, `
			insert into pgp_keys(fingerprint, packet, revoked, update_time)
			values($1, $2, $3, now())
			on conflict (fingerprint) do update set
				packet = excluded.packet,
				revoked = excluded.revoked,
				update_time = now();
		`, fingerprint, k.Packet, k.Revoked)
		if err != nil {
			return fmt.Errorf("error postgresql: AddKey: upsert key %s: %w", fingerprint, err)
		}

		// Upsert pgp_uids
		batch := &pgx.Batch{}
		insertUIDQuery := `
			insert into pgp_uids(fingerprint, uid, email, verified, verification_token, token_expires_at)
			values($1, $2, $3, $4, $5, $6)
			on conflict (fingerprint, uid) do nothing; 
		`
		for _, u := range k.Uids {
			batch.Queue(insertUIDQuery, fingerprint, u.UIDString, u.Email, u.Verify, u.Token, u.TokenExpires)
		}

		br := tx.SendBatch(ctx, batch)
		// Consume all results from the batch to ensure completion
		for i := 0; i < len(k.Uids); i++ {
			_, err = br.Exec()
			if err != nil {
				br.Close()
				return fmt.Errorf("error postgresql: AddKey: batch insert uid %d for key %s: %w", i, fingerprint, err)
			}
		}
		br.Close()
	}

	return tx.Commit(ctx)
}

func (s PostgresqlStorageRepo) VerifyUID(ctx context.Context, fingerprint, email, token string) error {
	tx, err := s.poll.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error postgresql: VerifyUID: begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// SELECT the UID to verify.
	var storedUID string // The full UID string (e.g., "Name <email>")
	var storedToken sql.NullString
	var tokenExpiresAt sql.NullTime
	var isVerified bool

	row := tx.QueryRow(ctx, `
		select uid, verification_token, token_expires_at, verified
		from pgp_uids
		where fingerprint = $1 and email = $2;
	`, fingerprint, email)

	if err = row.Scan(&storedUID, &storedToken, &tokenExpiresAt, &isVerified); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Not found
			return fmt.Errorf("error postgresql: VerifyUID: invalid verification token or link")
		}
		return fmt.Errorf("error postgresql: VerifyUID: failed to scan UID data: %w", err)
	}

	if isVerified {
		return fmt.Errorf("error postgresql: VerifyUID: UID for %s is already verified", email)
	}

	if storedToken.String == "" || storedToken.String != token {
		return fmt.Errorf("error postgresql: VerifyUID: invalid verification token or link")
	}

	if tokenExpiresAt.Time.Before(time.Now()) {
		return fmt.Errorf("error postgresql: VerifyUID: verification token has expired")
	}

	// UPDATE the UID status.
	result, err := tx.Exec(ctx, `
		update pgp_uids
		set verified = true,
			verification_token = null,
			token_expires_at = null
		where fingerprint = $1 and email = $2 and verification_token = $3;
	`, fingerprint, email, token)
	if err != nil {
		return fmt.Errorf("error postgresql: VerifyUID: failed to update UID verification status: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("error postgresql: VerifyUID: verification failed, token might be invalid or already used")
	}
	if rowsAffected > 1 {
		return fmt.Errorf("error postgresql: VerifyUID: multiple UIDs affected by verification (data integrity error!)")
	}

	return tx.Commit(ctx)
}

func (s PostgresqlStorageRepo) GetKey(ctx context.Context, fngprt string) ([]*service.PGPkey, error) {
	var packet string
	var fingerprint string
	var revoked bool
	var update_time time.Time

	row := s.poll.QueryRow(ctx, `
		select fingerprint, packet, revoked, update_time
		from pgp_keys
		where fingerprint ~* $1;
	`, fngprt)

	if err := row.Scan(&fingerprint, &packet, &revoked, &update_time); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repo.ErrKeyNotFound
		}
		return nil, fmt.Errorf("error postgresql: GetKey: failed to scan key data for fingerprint %s: %w", fngprt, err)
	}

	if !strings.Contains(fingerprint, fngprt) {
		return nil, repo.ErrKeyNotFound
	}

	// Fetch all VERIFIED UIDs for this key.
	rows, err := s.poll.Query(ctx, `
		select uid, email, verification_token, token_expires_at, verified
		from pgp_uids
		where fingerprint = $1 and verified = true;
	`, fngprt)
	if err != nil {
		return nil, fmt.Errorf("error postgresql: GetKey: failed to query UIDs for key %s: %w", fngprt, err)
	}
	defer rows.Close()

	var uids []*service.PGPUid
	for rows.Next() {

		uid := &service.PGPUid{}
		var token sql.NullString
		var tokenExpiresAt sql.NullTime
		if err := rows.Scan(&uid.UIDString, &uid.Email, &token, &tokenExpiresAt, &uid.Verify); err != nil {
			return nil, fmt.Errorf("error postgresql: GetKey: failed to scan UID row for key %s: %w", fngprt, err)
		}

		uid.Token = token.String
		uid.TokenExpires = tokenExpiresAt.Time

		uids = append(uids, uid)

	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error postgresql: GetKey: error after iterating UIDs for key %s: %w", fngprt, err)
	}

	pgpKey := &service.PGPkey{
		Fingerprint: fngprt,
		UpdateTime:  update_time,
		Packet:      packet,
		Revoked:     revoked,
		Uids:        uids, // Only verified UIDs included
	}
	return []*service.PGPkey{pgpKey}, nil
}

func (s PostgresqlStorageRepo) Index(ctx context.Context, q string) ([]*service.PGPkey, error) {
	// Search for matching fingerprints based on the query 'q'.
	fingerprintRows, err := s.poll.Query(ctx, `
		select distinct fingerprint
		from pgp_uids
		where (uid ~* $1 or email ~* $1 or fingerprint ~* $1) and verified = true;
	`, q)
	if err != nil {
		return nil, fmt.Errorf("error postgresql: Index: failed to query matching fingerprints for '%s': %w", q, err)
	}
	defer fingerprintRows.Close()

	var matchingFingerprints []string
	for fingerprintRows.Next() {
		var f string
		if err := fingerprintRows.Scan(&f); err != nil {
			return nil, fmt.Errorf("error postgresql: Index: failed to scan fingerprint: %w", err)
		}
		matchingFingerprints = append(matchingFingerprints, f)
	}
	if err = fingerprintRows.Err(); err != nil {
		return nil, fmt.Errorf("error postgresql: Index: error after iterating fingerprints: %w", err)
	}

	if len(matchingFingerprints) == 0 {
		return []*service.PGPkey{}, nil
	}

	// For each matching fingerprint, use GetKey to retrieve the full PGPKey object.
	var resultKeys []*service.PGPkey
	for _, fingerprint := range matchingFingerprints {
		keys, err := s.GetKey(ctx, fingerprint)
		if err != nil {
			if errors.Is(err, repo.ErrKeyNotFound) {
				continue
			}
			return nil, fmt.Errorf("error postgresql: Index: failed to retrieve key %s via GetKey: %w", fingerprint, err)
		}
		if len(keys) > 0 {
			resultKeys = append(resultKeys, keys[0])
		}
	}

	return resultKeys, nil
}
func (s PostgresqlStorageRepo) CleanupStaleKeys(ctx context.Context) (int, error) {
	// The SQL query will delete keys from pgp_keys that have no corresponding entries in pgp_uids.
	result, err := s.poll.Exec(ctx, `
		delete from pgp_keys pk
		where not exists (
			select 1 from pgp_uids pu where pu.fingerprint = pk.fingerprint
		);
	`)
	if err != nil {
		return 0, fmt.Errorf("error postgresql: CleanupStaleKeys: failed to delete stale keys: %w", err)
	}

	rowsAffected := int(result.RowsAffected())
	return rowsAffected, nil
}
