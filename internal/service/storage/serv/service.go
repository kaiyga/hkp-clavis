package serv

import (
	"context"
	"fmt"
	"log"

	"hkp-clavis/internal/model"
	storeRepo "hkp-clavis/internal/repo/storage"
	service "hkp-clavis/internal/service/storage"

	"github.com/ProtonMail/go-crypto/openpgp"
	hkp "github.com/emersion/go-openpgp-hkp"
)

type StorageService struct {
	hkp.Adder
	hkp.Lookuper
	//	mailService interface{}
	storage    storeRepo.StorageRepositotyInterface
	config     StorageServiceConfig
	keyManager *model.KeyManager
}

type StorageServiceConfig struct {
	defaultVerify bool
}

func New(storageRepository storeRepo.StorageRepositotyInterface, keyManager *model.KeyManager, defaultVerifyValue bool) service.StorageInterface {
	return StorageService{
		storage:    storageRepository,
		keyManager: keyManager,
		config: StorageServiceConfig{
			defaultVerify: defaultVerifyValue,
		},

		// Allocation manager
	}
}
func (s StorageService) Add(ctx context.Context, el openpgp.EntityList) ([]*model.PGPKey, error) {
	pgpKeys, release, err := s.keyManager.ConverterPgpToService(el, s.config.defaultVerify) // Assuming ConverterPgpToService might return an error now.
	defer release()

	if err != nil {
		return []*model.PGPKey{}, fmt.Errorf("service error: Add: failed to convert PGP entities: %w", err)
	}

	if len(pgpKeys) == 0 {
		return []*model.PGPKey{}, nil // No keys to add, nothing to do.
	}

	err = s.storage.AddKey(ctx, pgpKeys) // Pass context here
	if err != nil {
		return []*model.PGPKey{}, fmt.Errorf("service error: Add: failed to add keys to storage: %w", err)
	}

	return pgpKeys, nil
}

func (s StorageService) Get(ctx context.Context, req *hkp.LookupRequest) (openpgp.EntityList, error) {
	dbKeys, err := s.storage.Index(ctx, req.Search)
	if err != nil {
		return nil, fmt.Errorf("service error: Get: search failed: %w", err)
	}

	if len(dbKeys) == 0 {
		return nil, storeRepo.ErrKeyNotFound
	}

	defer s.keyManager.Release(dbKeys...)

	var finalEntityList openpgp.EntityList

	for _, dbKey := range dbKeys {
		filteredEntities, err := model.SanitizeAndFilterKey(dbKey)
		if err != nil {
			log.Printf("Warning: Get: failed to sanitize key %s: %v", dbKey.Fingerprint, err)
			continue
		}
		finalEntityList = append(finalEntityList, filteredEntities...)
	}

	if len(finalEntityList) == 0 {
		return nil, storeRepo.ErrKeyNotFound
	}

	return finalEntityList, nil
}

func (s StorageService) Index(ctx context.Context, req *hkp.LookupRequest) ([]hkp.IndexKey, error) {
	dbKeys, err := s.storage.Index(ctx, req.Search)
	if err != nil {
		return nil, fmt.Errorf("service error: Index: db index request for '%s': %w", req.Search, err)
	}
	defer s.keyManager.Release(dbKeys...)

	if len(dbKeys) == 0 {
		return nil, nil
	}

	var respIndex []hkp.IndexKey
	for _, dbKey := range dbKeys {
		filteredEntity, err := model.SanitizeAndFilterKey(dbKey)
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
