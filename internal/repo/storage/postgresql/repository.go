package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hkp-clavis/internal/model"
	repo "hkp-clavis/internal/repo/storage"
	"strings"
	"time"

	_ "embed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed structure.sql
var db_struct string

var (
	insertUid = `
			insert into pgp_uids(fingerprint, uid, email, verified, verification_token, token_expires_at)
			values($1, $2, $3, $4, $5, $6)
			on conflict (fingerprint, uid) do nothing; 
	`
	selectUid = `
		select uid, verification_token, token_expires_at, verified
		from pgp_uids
		where fingerprint = $1 and email = $2;
	`
	updateUidVerify = `
		update pgp_uids
		set verified = true,
			verification_token = null,
			token_expires_at = null
		where fingerprint = $1 and email = $2 and verification_token = $3;
	`
	fetchUidVerifed = `
		select uid, email, verification_token, token_expires_at, verified
		from pgp_uids
		where fingerprint = $1 and verified = true;
	`
	insertKey = `
			insert into pgp_keys(fingerprint, packet, revoked, update_time)
			values($1, $2, $3, now())
			on conflict (fingerprint) do update set
				packet = excluded.packet,
				revoked = excluded.revoked,
				update_time = now();
	`
	selectKeyByFingerprint = `
		select fingerprint, packet, revoked, update_time
		from pgp_keys
		where fingerprint ~* $1;
	`
	indexKeyByString = `
		SELECT 
			k.fingerprint, k.packet, k.revoked, k.update_time,
			u.uid, u.email, u.verified, u.verification_token, u.token_expires_at
		FROM pgp_keys k
		JOIN pgp_uids u ON k.fingerprint = u.fingerprint
		WHERE k.fingerprint IN (
			SELECT DISTINCT fingerprint 
			FROM pgp_uids 
			WHERE (uid ~* $1 OR email ~* $1 OR fingerprint ~* $1) AND verified = true
		)
		ORDER BY k.fingerprint;
	`
	cleanupStaleKeys = `
        delete from pgp_keys pk
        where not exists (
            select 1 from pgp_uids pu where pu.fingerprint = pk.fingerprint
        );
    `
)

type PostgresqlStorageRepo struct {
	poll    *pgxpool.Pool
	keyMngr *model.KeyManager
}

// Get context, url
// Return postgresql repository
func New(ctx context.Context, pool *pgxpool.Pool, keyManager *model.KeyManager) repo.StorageRepositotyInterface {
	_, err := pool.Exec(ctx, db_struct)
	if err != nil {
		panic(err)
	}

	return PostgresqlStorageRepo{
		poll: pool,
		// Allocation manager
		keyMngr: keyManager,
	}
}

func (s PostgresqlStorageRepo) AddKey(ctx context.Context, keys []*model.PGPKey) error {
	tx, err := s.poll.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error postgresql: AddKey: begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, k := range keys {
		fingerprint := k.Fingerprint
		// Upsert pgp_keys
		_, err = tx.Exec(ctx, insertKey, fingerprint, k.Packet, k.Revoked)
		if err != nil {
			return fmt.Errorf("error postgresql: AddKey: upsert key %s: %w", fingerprint, err)
		}

		// Upsert pgp_uids
		batch := &pgx.Batch{}
		for _, u := range k.Uids {
			batch.Queue(insertUid, fingerprint, u.UIDString, u.Email, u.Verify, u.Token, u.TokenExpires)
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

	row := tx.QueryRow(ctx, selectUid, fingerprint, email)

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
	result, err := tx.Exec(ctx, updateUidVerify, fingerprint, email, token)
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

func (s PostgresqlStorageRepo) GetKey(ctx context.Context, fngprt string) (res []*model.PGPKey, err error) {
	pgpKey := s.keyMngr.Get()

	defer func() {
		if err != nil {
			s.keyMngr.Release(pgpKey)
		}
	}()

	row := s.poll.QueryRow(ctx, selectKeyByFingerprint, fngprt)

	if err = row.Scan(&pgpKey.Fingerprint, &pgpKey.Packet, &pgpKey.Revoked, &pgpKey.UpdateTime); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repo.ErrKeyNotFound
		}
		return nil, fmt.Errorf("error postgresql: GetKey: scan error: %w", err)
	}

	if !strings.Contains(pgpKey.Fingerprint, fngprt) {
		return nil, repo.ErrKeyNotFound
	}

	rows, err := s.poll.Query(ctx, fetchUidVerifed, pgpKey.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("error postgresql: GetKey: query uids error: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		uid := s.keyMngr.GetUid()
		var token sql.NullString
		var tokenExpiresAt sql.NullTime

		if err = rows.Scan(&uid.UIDString, &uid.Email, &token, &tokenExpiresAt, &uid.Verify); err != nil {
			s.keyMngr.ReleaseUid(uid)
			return nil, err
		}

		uid.Token = token.String
		uid.TokenExpires = tokenExpiresAt.Time
		pgpKey.Uids = append(pgpKey.Uids, uid)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return []*model.PGPKey{pgpKey}, nil
}

func (s PostgresqlStorageRepo) Index(ctx context.Context, q string) (resultKeys []*model.PGPKey, err error) {
	rows, err := s.poll.Query(ctx, indexKeyByString, q)
	if err != nil {
		return nil, fmt.Errorf("postgresql: Index query failed: %w", err)
	}
	defer rows.Close()

	defer func() {
		if err != nil {
			s.keyMngr.Release(resultKeys...)
		}
	}()

	var currentKey *model.PGPKey

	for rows.Next() {
		var fng, packet string
		var revoked bool
		var updateTime time.Time

		uidObj := s.keyMngr.GetUid()
		var token sql.NullString
		var tokenExpiresAt sql.NullTime

		err = rows.Scan(
			&fng, &packet, &revoked, &updateTime,
			&uidObj.UIDString, &uidObj.Email, &uidObj.Verify, &token, &tokenExpiresAt,
		)
		if err != nil {
			s.keyMngr.ReleaseUid(uidObj)
			return nil, err
		}

		uidObj.Token = token.String
		uidObj.TokenExpires = tokenExpiresAt.Time
		uidObj.Fingerprint = fng

		if currentKey == nil || currentKey.Fingerprint != fng {
			currentKey = s.keyMngr.Get()
			currentKey.Fingerprint = fng
			currentKey.Packet = packet
			currentKey.Revoked = revoked
			currentKey.UpdateTime = updateTime

			resultKeys = append(resultKeys, currentKey)
		}

		currentKey.Uids = append(currentKey.Uids, uidObj)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("postgresql: Index rows iteration error: %w", err)
	}

	return resultKeys, nil
}

func (s PostgresqlStorageRepo) CleanupStaleKeys(ctx context.Context) (int, error) {
	result, err := s.poll.Exec(ctx, cleanupStaleKeys)
	if err != nil {
		return 0, fmt.Errorf("error postgresql: CleanupStaleKeys: failed to delete stale keys: %w", err)
	}

	rowsAffected := int(result.RowsAffected())
	return rowsAffected, nil
}
