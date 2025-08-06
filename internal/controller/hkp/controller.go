package hkp

import (
	"gadrid/internal/service/storage"

	"github.com/ProtonMail/go-crypto/openpgp"
	hkp "github.com/emersion/go-openpgp-hkp"
)

type HkpController struct {
	hkp.Adder
	hkp.Lookuper
	storage storage.StorageInterface
	// verify
}

func New(st storage.StorageInterface) (HkpController, error) {
	return HkpController{
		storage: st,
	}, nil
}

func (s HkpController) Add(k openpgp.EntityList) error {
	return nil
}

func (s HkpController) Get(r *hkp.LookupRequest) (openpgp.EntityList, error) {
	return openpgp.EntityList{}, nil
}

func (s HkpController) Index(r *hkp.LookupRequest) ([]hkp.IndexKey, error) {
	return []hkp.IndexKey{}, nil
}
