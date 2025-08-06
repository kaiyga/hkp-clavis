package postgresql_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	testDBConnString = "postgresql://test_user:test_password@localhost:5433/test_hagrid_db"
)

// setupTestDBPool initializes a connection pool for testing and ensures schema is created.
func setupTestDBPool(t testing.TB) *pgxpool.Pool {
	// Allow time for Docker container to start
	time.Sleep(2 * time.Second)

	pool, err := pgxpool.New(context.Background(), testDBConnString)
	if err != nil {
		t.Fatalf("Failed to create test DB pool: %v", err)
	}

	// Ping to ensure connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Fatalf("Failed to ping test DB: %v", err)
	}

	// Initialize schema (your dbStructureSQL from //go:embed)
	// Ensure dbStructureSQL is accessible here.
	// If it's embedded in main repository.go, you might need to make NewPostgresqlStorageRepo public
	// or re-embed it directly in the test file (less ideal).
	// Best: embed it in a separate package for common DB utils or make a separate TestInitDB function.
	_, err = pool.Exec(context.Background(), dbStructureSQL)
	if err != nil {
		pool.Close()
		t.Fatalf("Failed to initialize test DB schema: %v", err)
	}

	// Enable pg_trgm for testing Index method if needed
	_, err = pool.Exec(context.Background(), "CREATE EXTENSION IF NOT EXISTS pg_trgm;")
	if err != nil {
		pool.Close()
		t.Fatalf("Failed to enable pg_trgm extension: %v", err)
	}
	// Also create the specific GIN indexes
	_, err = pool.Exec(context.Background(), "CREATE INDEX IF NOT EXISTS idx_pgp_uids_uid_gin ON pgp_uids USING GIN (uid gin_trgm_ops);")
	if err != nil {
		pool.Close()
		t.Fatalf("Failed to create idx_pgp_uids_uid_gin: %v", err)
	}
	_, err = pool.Exec(context.Background(), "CREATE INDEX IF NOT EXISTS idx_pgp_uids_email_gin ON pgp_uids USING GIN (email gin_trgm_ops);")
	if err != nil {
		pool.Close()
		t.Fatalf("Failed to create idx_pgp_uids_email_gin: %v", err)
	}

	return pool
}

// cleanupTestDB clears all data from relevant tables.
func cleanupTestDB(t testing.TB, pool *pgxpool.Pool) {
	// Truncate tables, CASCADE if needed
	_, err := pool.Exec(context.Background(), `
        truncate table pgp_uids cascade;
        truncate table pgp_keys cascade;
    `)
	if err != nil {
		t.Errorf("Failed to cleanup test DB: %v", err)
	}
}
