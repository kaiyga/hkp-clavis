package postgresql_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "embed"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	repository "gadrid/internal/repo/storage"
	psqlrepo "gadrid/internal/repo/storage/postgresql"
	service "gadrid/internal/service/storage"
)

//go:embed structure.sql
var dbStructureSQL string

func TestPostgresqlStorageRepo_AddKey(t *testing.T) {
	pool := setupTestDBPool(t)
	defer pool.Close()
	defer cleanupTestDB(t, pool)

	repo := psqlrepo.New(context.Background(), pool)

	ctx := context.Background()

	// --- Test Case 1: Add a new key ---
	t.Run("Add new key successfully", func(t *testing.T) {
		key := &service.PGPkey{
			Fingerprint: "FINGERPRINT_NEW_KEY",
			Packet:      "-----BEGIN PGP PUBLIC KEY BLOCK-----NEW_KEY_PACKET-----END PGP PUBLIC KEY BLOCK-----",
			Revoked:     false,
			Uids: []*service.PGPUid{
				{UIDString: "New User <new@example.com>", Email: "new@example.com", Verify: false, Token: "token1", TokenExpires: time.Now().Add(time.Hour)},
			},
		}
		err := repo.AddKey(ctx, []*service.PGPkey{key})
		require.NoError(t, err)

		// Verify key was added
		retrievedKeys, err := repo.GetKey(ctx, key.Fingerprint)
		require.NoError(t, err)
		require.Len(t, retrievedKeys, 1)
		assert.Equal(t, key.Fingerprint, retrievedKeys[0].Fingerprint)
		assert.Equal(t, key.Packet, retrievedKeys[0].Packet)
		assert.False(t, retrievedKeys[0].Revoked)
		assert.Empty(t, retrievedKeys[0].Uids) // GetKey only returns verified UIDs

		// Verify UID was added (check DB directly for unverified)
		var uidCount int
		err = pool.QueryRow(ctx, "select count(*) from pgp_uids where fingerprint = $1 and uid = $2", key.Fingerprint, "New User <new@example.com>").Scan(&uidCount)
		require.NoError(t, err)
		assert.Equal(t, 1, uidCount)
	})

	// --- Test Case 2: Update an existing key (packet, revoked status) ---
	t.Run("Update existing key packet and revoked status", func(t *testing.T) {
		initialKey := &service.PGPkey{
			Fingerprint: "FINGERPRINT_EXISTING",
			Packet:      "-----BEGIN PGP PUBLIC KEY BLOCK-----INITIAL_PACKET-----END PGP PUBLIC KEY BLOCK-----",
			Revoked:     false,
			Uids: []*service.PGPUid{
				{UIDString: "Existing User <existing@example.com>", Email: "existing@example.com", Verify: false, Token: "initial_token", TokenExpires: time.Now().Add(time.Hour)},
			},
		}
		err := repo.AddKey(ctx, []*service.PGPkey{initialKey})
		require.NoError(t, err)

		// Simulate an update: new packet, revoked true
		updatedKey := &service.PGPkey{
			Fingerprint: "FINGERPRINT_EXISTING",
			Packet:      "-----BEGIN PGP PUBLIC KEY BLOCK-----UPDATED_PACKET-----END PGP PUBLIC KEY BLOCK-----",
			Revoked:     true,
			Uids: []*service.PGPUid{
				{UIDString: "Existing User <existing@example.com>", Email: "existing@example.com", Verify: false, Token: "updated_token", TokenExpires: time.Now().Add(time.Hour * 2)},
			},
		}
		err = repo.AddKey(ctx, []*service.PGPkey{updatedKey})
		require.NoError(t, err)

		// Verify key was updated
		retrievedKeys, err := repo.GetKey(ctx, updatedKey.Fingerprint)
		require.NoError(t, err)
		require.Len(t, retrievedKeys, 1)
		assert.Equal(t, updatedKey.Fingerprint, retrievedKeys[0].Fingerprint)
		assert.Equal(t, updatedKey.Packet, retrievedKeys[0].Packet)
		assert.True(t, retrievedKeys[0].Revoked)

		// Verify UID was NOT updated (due to on conflict do nothing)
		var storedToken string
		err = pool.QueryRow(ctx, "select verification_token from pgp_uids where fingerprint = $1 and uid = $2", updatedKey.Fingerprint, "Existing User <existing@example.com>").Scan(&storedToken)
		require.NoError(t, err)
		assert.Equal(t, "initial_token", storedToken) // Should still be initial_token
	})

	// --- Test Case 3: Add new UID to existing key ---
	t.Run("Add new UID to existing key", func(t *testing.T) {
		key := &service.PGPkey{
			Fingerprint: "FINGERPRINT_ADD_UID",
			Packet:      "-----BEGIN PGP PUBLIC KEY BLOCK-----ADD_UID_KEY-----END PGP PUBLIC KEY BLOCK-----",
			Revoked:     false,
			Uids: []*service.PGPUid{
				{UIDString: "First UID <first@example.com>", Email: "first@example.com", Verify: false, Token: "token_first", TokenExpires: time.Now().Add(time.Hour)},
			},
		}
		err := repo.AddKey(ctx, []*service.PGPkey{key})
		require.NoError(t, err)

		// Add a second UID to the same key
		updatedKey := &service.PGPkey{
			Fingerprint: "FINGERPRINT_ADD_UID",
			Packet:      "-----BEGIN PGP PUBLIC KEY BLOCK-----ADD_UID_KEY_UPDATED-----END PGP PUBLIC KEY BLOCK-----",
			Revoked:     false,
			Uids: []*service.PGPUid{
				{UIDString: "First UID <first@example.com>", Email: "first@example.com", Verify: false, Token: "token_first", TokenExpires: time.Now().Add(time.Hour)},
				{UIDString: "Second UID <second@example.com>", Email: "second@example.com", Verify: false, Token: "token_second", TokenExpires: time.Now().Add(time.Hour)},
			},
		}
		err = repo.AddKey(ctx, []*service.PGPkey{updatedKey})
		require.NoError(t, err)

		// Verify both UIDs exist
		var uidCount int
		err = pool.QueryRow(ctx, "select count(*) from pgp_uids where fingerprint = $1", updatedKey.Fingerprint).Scan(&uidCount)
		require.NoError(t, err)
		assert.Equal(t, 2, uidCount)
	})
}

func TestPostgresqlStorageRepo_VerifyUID(t *testing.T) {
	pool := setupTestDBPool(t)
	defer pool.Close()
	defer cleanupTestDB(t, pool)

	repo := psqlrepo.New(context.Background(), pool)
	ctx := context.Background()

	// Add a key with an unverified UID
	keyFingerprint := "FINGERPRINT_VERIFY_KEY"
	uidEmail := "verify@test.com"
	uidToken := "verifytoken123"
	uidExpires := time.Now().Add(time.Hour)

	err := repo.AddKey(ctx, []*service.PGPkey{
		{
			Fingerprint: keyFingerprint,
			Packet:      "...",
			Revoked:     false,
			Uids: []*service.PGPUid{
				{UIDString: "Verify Me <" + uidEmail + ">", Email: uidEmail, Verify: false, Token: uidToken, TokenExpires: uidExpires},
			},
		},
	})
	require.NoError(t, err)

	t.Run("Successfully verify UID", func(t *testing.T) {
		err := repo.VerifyUID(ctx, keyFingerprint, uidEmail, uidToken)
		require.NoError(t, err)

		// Verify status in DB
		var verified bool
		var token sql.NullString
		var expires sql.NullTime
		err = pool.QueryRow(ctx, "select verified, verification_token, token_expires_at from pgp_uids where fingerprint = $1 and email = $2", keyFingerprint, uidEmail).Scan(&verified, &token, &expires)
		require.NoError(t, err)
		assert.True(t, verified)
		assert.False(t, token.Valid)   // Should be null
		assert.False(t, expires.Valid) // Should be null
	})

	t.Run("Fail verification with wrong token", func(t *testing.T) {
		err := repo.VerifyUID(ctx, keyFingerprint, "wrongverify@email.io", "wrongtoken")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid verification token or link")

		// Ensure status remains verified from previous successful run
		var verified bool
		err = pool.QueryRow(ctx, "select verified from pgp_uids where fingerprint = $1 and email = $2", keyFingerprint, uidEmail).Scan(&verified)
		require.NoError(t, err)
		assert.True(t, verified)
	})

	t.Run("Fail verification for already verified UID", func(t *testing.T) {
		err := repo.VerifyUID(ctx, keyFingerprint, uidEmail, uidToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already verified")
	})

	t.Run("Fail verification with expired token", func(t *testing.T) {
		// Add another key with an expired token
		expiredFingerprint := "FINGERPRINT_EXPIRED_TOKEN"
		expiredEmail := "expired@test.com"
		expiredToken := "expiredtoken"
		expiredTime := time.Now().Add(-time.Hour)

		err := repo.AddKey(ctx, []*service.PGPkey{
			{
				Fingerprint: expiredFingerprint,
				Packet:      "...",
				Revoked:     false,
				Uids: []*service.PGPUid{
					{UIDString: "Expired <" + expiredEmail + ">", Email: expiredEmail, Verify: false, Token: expiredToken, TokenExpires: expiredTime},
				},
			},
		})
		require.NoError(t, err)

		err = repo.VerifyUID(ctx, expiredFingerprint, expiredEmail, expiredToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token has expired")

		// Ensure it's still unverified
		var verified bool
		err = pool.QueryRow(ctx, "select verified from pgp_uids where fingerprint = $1 and email = $2", expiredFingerprint, expiredEmail).Scan(&verified)
		require.NoError(t, err)
		assert.False(t, verified)
	})
}

func TestPostgresqlStorageRepo_GetKey(t *testing.T) {
	pool := setupTestDBPool(t)
	defer pool.Close()
	defer cleanupTestDB(t, pool)

	repo := psqlrepo.New(context.Background(), pool)
	ctx := context.Background()

	// Add a key with mixed UIDs (verified and unverified)
	testFingerprint := "FINGERPRINT_GET_KEY"
	err := repo.AddKey(ctx, []*service.PGPkey{
		{
			Fingerprint: testFingerprint,
			Packet:      "PACKET_DATA",
			Revoked:     false,
			Uids: []*service.PGPUid{
				{UIDString: "Verified User <verified@example.com>", Email: "verified@example.com", Verify: false, Token: "tok_v", TokenExpires: time.Now().Add(time.Hour)},
				{UIDString: "Unverified User <unverified@example.com>", Email: "unverified@example.com", Verify: false, Token: "tok_uv", TokenExpires: time.Now().Add(time.Hour)},
				{UIDString: "Another Verified <another@example.com>", Email: "another@example.com", Verify: false, Token: "tok_av", TokenExpires: time.Now().Add(time.Hour)},
			},
		},
	})
	require.NoError(t, err)

	// Manually verify two UIDs for the test
	require.NoError(t, repo.VerifyUID(ctx, testFingerprint, "verified@example.com", "tok_v"))
	require.NoError(t, repo.VerifyUID(ctx, testFingerprint, "another@example.com", "tok_av"))

	t.Run("Retrieve key with only verified UIDs", func(t *testing.T) {
		retrievedKeys, err := repo.GetKey(ctx, testFingerprint)
		require.NoError(t, err)
		require.Len(t, retrievedKeys, 1)

		key := retrievedKeys[0]
		assert.Equal(t, testFingerprint, key.Fingerprint)
		assert.Equal(t, "PACKET_DATA", key.Packet)
		assert.False(t, key.Revoked)
		assert.Len(t, key.Uids, 2) // Only 2 verified UIDs should be returned

		// Check UIDs content
		foundEmails := make(map[string]bool)
		for _, uid := range key.Uids {
			assert.True(t, uid.Verify) // All returned UIDs must be verified
			foundEmails[uid.Email] = true
		}
		assert.True(t, foundEmails["verified@example.com"])
		assert.True(t, foundEmails["another@example.com"])
		assert.False(t, foundEmails["unverified@example.com"]) // Should not be present
	})

	t.Run("Retrieve non-existent key", func(t *testing.T) {
		k, err := repo.GetKey(ctx, "NON_EXISTENT_FINGERPRINT")
		assert.Len(t, k, 0)
		require.Error(t, err)
		assert.True(t, errors.Is(err, repository.ErrKeyNotFound))
	})
}

func TestPostgresqlStorageRepo_Index(t *testing.T) {
	pool := setupTestDBPool(t)
	defer pool.Close()
	defer cleanupTestDB(t, pool)

	repo := psqlrepo.New(context.Background(), pool)
	ctx := context.Background()

	// Add multiple keys with various UIDs
	keysToLoad := []*service.PGPkey{
		{
			Fingerprint: "FINGERPRINT_ALPHA", Packet: "alpha_packet", Revoked: false,
			Uids: []*service.PGPUid{
				{UIDString: "Alpha User <alpha@example.com>", Email: "alpha@example.com", Verify: false, Token: "t1", TokenExpires: time.Now().Add(time.Hour)},
				{UIDString: "Test Alpha <testalpha@mail.com>", Email: "testalpha@mail.com", Verify: false, Token: "t2", TokenExpires: time.Now().Add(time.Hour)},
			},
		},
		{
			Fingerprint: "FINGERPRINT_BETA", Packet: "beta_packet", Revoked: false,
			Uids: []*service.PGPUid{
				{UIDString: "Beta User <beta@example.com>", Email: "beta@example.com", Verify: false, Token: "t3", TokenExpires: time.Now().Add(time.Hour)},
			},
		},
		{
			Fingerprint: "FINGERPRINT_GAMMA", Packet: "gamma_packet", Revoked: false,
			Uids: []*service.PGPUid{
				{UIDString: "Gamma User <gamma@example.com>", Email: "gamma@example.com", Verify: false, Token: "t4", TokenExpires: time.Now().Add(time.Hour)},
				{UIDString: "Test Gamma <testgamma@mail.com>", Email: "testgamma@mail.com", Verify: false, Token: "t5", TokenExpires: time.Now().Add(time.Hour)},
			},
		},
	}
	require.NoError(t, repo.AddKey(ctx, keysToLoad))

	// Manually verify some UIDs
	require.NoError(t, repo.VerifyUID(ctx, "FINGERPRINT_ALPHA", "alpha@example.com", "t1"))
	require.NoError(t, repo.VerifyUID(ctx, "FINGERPRINT_BETA", "beta@example.com", "t3"))
	require.NoError(t, repo.VerifyUID(ctx, "FINGERPRINT_GAMMA", "testgamma@mail.com", "t5")) // Verify only one UID for gamma

	t.Run("Search by full UID string", func(t *testing.T) {
		results, err := repo.Index(ctx, "Alpha User")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "FINGERPRINT_ALPHA", results[0].Fingerprint)
		assert.Len(t, results[0].Uids, 1) // Only 1 verified UID from alpha
		assert.Equal(t, "alpha@example.com", results[0].Uids[0].Email)
	})

	t.Run("Search by email part", func(t *testing.T) {
		results, err := repo.Index(ctx, "mail")
		require.NoError(t, err)
		require.Len(t, results, 1) // Only FINGERPRINT_GAMMA has a *verified* UID with @mail.com
		assert.Equal(t, "FINGERPRINT_GAMMA", results[0].Fingerprint)
		assert.Len(t, results[0].Uids, 1)
		assert.Equal(t, "testgamma@mail.com", results[0].Uids[0].Email)
	})

	t.Run("Search by part of name (case-insensitive)", func(t *testing.T) {
		results, err := repo.Index(ctx, "beta")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "FINGERPRINT_BETA", results[0].Fingerprint)
		assert.Len(t, results[0].Uids, 1)
		assert.Equal(t, "beta@example.com", results[0].Uids[0].Email)
	})

	t.Run("Search for non-existent query", func(t *testing.T) {
		results, err := repo.Index(ctx, "nonexistent")
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("Search for unverified UID (should not return key)", func(t *testing.T) {
		// FINGERPRINT_ALPHA has an unverified UID "Test Alpha <testalpha@mail.com>"
		results, err := repo.Index(ctx, "Test Alpha")
		require.NoError(t, err)
		assert.Empty(t, results)
	})
}
