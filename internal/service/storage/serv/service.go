package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	storeRepo "gadrid/internal/repo/storage"
	service "gadrid/internal/service/storage"

	"github.com/ProtonMail/go-crypto/openpgp"
	hkp "github.com/emersion/go-openpgp-hkp"
)

type StorageService struct {
	hkp.Adder
	hkp.Lookuper
	//	mailService interface{}
	storage storeRepo.StorageRepositotyInterface
}

func New(storageRepository storeRepo.StorageRepositotyInterface) StorageService {
	return StorageService{
		storage: storageRepository,
	}
}
func (s StorageService) Add(el openpgp.EntityList) error {
	fmt.Println(el)
	pgpKeys, err := service.ConverterPgpToService(el) // Assuming ConverterPgpToService might return an error now.
	if err != nil {
		return fmt.Errorf("service error: Add: failed to convert PGP entities: %w", err)
	}

	if len(pgpKeys) == 0 {
		return nil // No keys to add, nothing to do.
	}

	// 2. Pass the context from this service method down to the storage layer.
	// 3. ALWAYS check the error returned by the storage layer.
	err = s.storage.AddKey(context.Background(), pgpKeys) // Pass context here
	if err != nil {
		return fmt.Errorf("service error: Add: failed to add keys to storage: %w", err)
	}

	return nil // Successfully processed
}

// Get key by fingerprint
// In Specification "op=get" fingerprint and uid
// FUTUE TE IPSUM specification! Only fingerprint search!

func (s StorageService) Get(req *hkp.LookupRequest) (openpgp.EntityList, error) {

	req.Search = strings.Trim(req.Search, "0x")

	if len(req.Search) <= 15 {
		return nil, fmt.Errorf("service error: Get: Low entropy string for search")
	}

	dbKeys, err := s.storage.GetKey(context.Background(), req.Search)
	if err != nil {
		if errors.Is(err, storeRepo.ErrKeyNotFound) {
			return nil, fmt.Errorf("service error: Get: key %s not found: %w", req.Search, err)
		}
		return nil, fmt.Errorf("service error: Get: db request failed for key %s: %w", req.Search, err)
	}

	if len(dbKeys) == 0 {
		return nil, fmt.Errorf("service error: Get: key %s not found (repository returned empty list): %w", req.Search, storeRepo.ErrKeyNotFound)
	}

	dbKey := dbKeys[0]

	filteredEntity, err := s.sanitizeAndFilterKey(dbKey)
	if err != nil {
		return nil, fmt.Errorf("service error: Get: failed to sanitize and filter key %s: %w", dbKey.Fingerprint, err)
	}

	return filteredEntity, nil
}

func (s StorageService) Index(req *hkp.LookupRequest) ([]hkp.IndexKey, error) {

	if len(req.Search) < 5 {
		return nil, fmt.Errorf("service error: Index: short string for search")
	}

	dbKeys, err := s.storage.Index(context.Background(), req.Search) // Pass ctx here
	if err != nil {
		return nil, fmt.Errorf("service error: Index: db index request for '%s': %w", req.Search, err) // Include original error
	}

	if len(dbKeys) == 0 {
		return nil, nil
	}

	var respIndex []hkp.IndexKey
	for _, dbKey := range dbKeys {
		filteredEntity, err := s.sanitizeAndFilterKey(dbKey)
		if err != nil {
			log.Printf("Warning: service error: Index: failed to sanitize and filter key %s: %v, skipping.", dbKey.Fingerprint, err)
			continue // Skip this problematic key
		}

		for _, fpk := range filteredEntity {
			idxKey, err := hkp.IndexKeyFromEntity(fpk)
			if err != nil {
				log.Printf("Warning: service error: Index: failed to convert entity %s to IndexKey: %v, skipping.", dbKey.Fingerprint, err)
				continue
			}
			respIndex = append(respIndex, *idxKey)
		}
	}

	if len(respIndex) == 0 {
		return nil, fmt.Errorf("service error: Index: no valid index keys found after processing for '%s': %w", req.Search, storeRepo.ErrKeyNotFound)
	}

	return respIndex, nil
}

func (s StorageService) sanitizeAndFilterKey(dbKey *service.PGPkey) (openpgp.EntityList, error) {

	parsedEntities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(dbKey.Packet))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key packet for %s: %w", dbKey.Fingerprint, err)
	}

	if len(parsedEntities) == 0 {
		return nil, fmt.Errorf("parsed key packet for %s yielded no entities", dbKey.Fingerprint)
	}
	var respEntities openpgp.EntityList
	for _, e := range parsedEntities {
		if e == nil {
			return nil, fmt.Errorf("no entity with matching fingerprint %s found in parsed packet from DB", dbKey.Fingerprint)
		}
		verifiedUIDStringsFromDB := make(map[string]struct{})
		for _, dbUID := range dbKey.Uids {
			verifiedUIDStringsFromDB[dbUID.UIDString] = struct{}{}
		}
		filteredIdentities := make(map[string]*openpgp.Identity)
		for identityKey, identity := range e.Identities {
			if _, isVerified := verifiedUIDStringsFromDB[identity.Name]; isVerified {
				filteredIdentities[identityKey] = identity // Keep this identity
			}
		}
		e.Identities = filteredIdentities
		respEntities = append(respEntities, e)
	}
	return respEntities, nil
}
