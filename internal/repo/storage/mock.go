package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"hkp-clavis/internal/model"
	// Adjust this import path
)

// InMemStorageMock is a mock implementation of PGPKeyStorage for testing purposes.
// It stores data in memory, mimicking database operations.
type InMemStorageMock struct {
	keys map[string]*model.PGPKey
	uids map[string]map[string]*model.PGPUid // fingerprint -> uid_string -> UID
	mu   sync.RWMutex                        // Mutex for concurrent access safety
}

// NewInMemStorageMock creates a new in-memory mock storage.
func NewInMemStorageMock() *InMemStorageMock {
	return &InMemStorageMock{
		keys: make(map[string]*model.PGPKey),
		uids: make(map[string]map[string]*model.PGPUid),
	}
}

// AddKey implements PGPKeyStorage interface for the mock.
// See PGPKeyStorage interface for documentation.
func (m *InMemStorageMock) AddKey(ctx context.Context, keys []*model.PGPKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, k := range keys {
		// Simulate UPSERT for pgp_keys
		m.keys[k.Fingerprint] = &model.PGPKey{ // Deep copy
			Fingerprint: k.Fingerprint,
			Packet:      k.Packet,
			Revoked:     k.Revoked,
			// Uids are handled separately, so this slice will be empty here in the key itself
		}

		// Ensure the inner map exists for UIDs
		if _, ok := m.uids[k.Fingerprint]; !ok {
			m.uids[k.Fingerprint] = make(map[string]*model.PGPUid)
		}

		// Simulate INSERT (ON CONFLICT DO NOTHING) for pgp_uids
		for _, u := range k.Uids {
			if _, exists := m.uids[k.Fingerprint][u.UIDString]; !exists {
				m.uids[k.Fingerprint][u.UIDString] = &model.PGPUid{ // Deep copy
					UIDString:    u.UIDString,
					Email:        u.Email,
					Verify:       u.Verify,
					Token:        u.Token,
					TokenExpires: u.TokenExpires,
				}
			}
		}
	}
	return nil
}

// VerifyUID implements PGPKeyStorage interface for the mock.
// See PGPKeyStorage interface for documentation.
func (m *InMemStorageMock) VerifyUID(ctx context.Context, fingerprint, email, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keyUids, ok := m.uids[fingerprint]
	if !ok {
		return fmt.Errorf("invalid verification token or link") // Mimic no matching entry
	}

	var targetUID *model.PGPUid
	var targetUIDString string // To be used as key in the map for update
	for uidStr, uid := range keyUids {
		if uid.Email == email {
			targetUID = uid
			targetUIDString = uidStr
			break
		}
	}

	if targetUID == nil {
		return fmt.Errorf("invalid verification token or link") // Mimic no matching entry by email
	}

	if targetUID.Verify {
		return fmt.Errorf("UID for %s is already verified", email)
	}
	if targetUID.Token == "" || targetUID.Token != token {
		return fmt.Errorf("invalid verification token or link")
	}
	if targetUID.TokenExpires.Before(time.Now()) {
		return fmt.Errorf("verification token has expired")
	}

	// Simulate update
	targetUID.Verify = true
	targetUID.Token = ""                 // Simulate setting to null
	targetUID.TokenExpires = time.Time{} // Simulate setting to null

	// Ensure the updated UID is correctly stored back in the map
	m.uids[fingerprint][targetUIDString] = targetUID

	return nil
}

// GetKey implements PGPKeyStorage interface for the mock.
// See PGPKeyStorage interface for documentation.
func (m *InMemStorageMock) GetKey(ctx context.Context, fingerprint string) ([]*model.PGPKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pgpKey, ok := m.keys[fingerprint]
	if !ok {
		return nil, ErrKeyNotFound // Use the specific error defined in the interface package
	}

	// Create a deep copy of the key
	resultKey := &model.PGPKey{
		Fingerprint: pgpKey.Fingerprint,
		Packet:      pgpKey.Packet,
		Revoked:     pgpKey.Revoked,
		Uids:        []*model.PGPUid{}, // Only add verified UIDs
	}

	// Filter UIDs by 'verified = true'
	if keyUids, ok := m.uids[fingerprint]; ok {
		for _, uid := range keyUids {
			if uid.Verify {
				// Deep copy the UID
				resultKey.Uids = append(resultKey.Uids, &model.PGPUid{
					UIDString:    uid.UIDString,
					Email:        uid.Email,
					Verify:       uid.Verify,
					Token:        uid.Token,
					TokenExpires: uid.TokenExpires,
				})
			}
		}
	}

	return []*model.PGPKey{resultKey}, nil
}

// Index implements PGPKeyStorage interface for the mock.
// See PGPKeyStorage interface for documentation.
func (m *InMemStorageMock) Index(ctx context.Context, q string) ([]*model.PGPKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matchedFingerprints := make(map[string]bool)
	lowerQ := strings.ToLower(q) // Simulate case-insensitive search

	for f, uidMap := range m.uids {
		for _, uid := range uidMap {
			// Simulate case-insensitive substring match for regex.
			// For a more accurate mock, you'd use the 'regexp' package here.
			if strings.Contains(strings.ToLower(uid.UIDString), lowerQ) ||
				strings.Contains(strings.ToLower(uid.Email), lowerQ) {
				matchedFingerprints[f] = true
			}
		}
	}

	var resultKeys []*model.PGPKey
	for f := range matchedFingerprints {
		// Reuse GetKey logic from mock (which filters for verified UIDs)
		keys, err := m.GetKey(ctx, f)
		if err == nil && len(keys) > 0 { // Check error from GetKey (e.g., ErrKeyNotFound)
			resultKeys = append(resultKeys, keys[0])
		}
	}

	return resultKeys, nil
}
