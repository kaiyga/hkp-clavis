package storage

import (
	"context"
	"hkp-clavis/internal/model"

	"github.com/ProtonMail/go-crypto/openpgp"
	hkp "github.com/emersion/go-openpgp-hkp"
)

type StorageInterface interface {
	Add(ctx context.Context, el openpgp.EntityList) ([]*model.PGPKey, error)
	Get(ctx context.Context, r *hkp.LookupRequest) (openpgp.EntityList, error)
	Index(ctx context.Context, r *hkp.LookupRequest) ([]hkp.IndexKey, error)
}
