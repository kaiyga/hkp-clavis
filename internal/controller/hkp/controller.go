package hkp

import (
	"context"
	"fmt"
	"hkp-clavis/internal/service/storage"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	hkp "github.com/emersion/go-openpgp-hkp"
)

type HkpController struct {
	hkp.Adder
	hkp.Lookuper
	storageService storage.StorageInterface
	// verifyService
}

const (
	defaultTimeout = 30 * time.Second
	minEntropy     = 15
)

func New(st storage.StorageInterface) (HkpController, error) {
	return HkpController{
		storageService: st,
	}, nil
}

func (s HkpController) Add(el openpgp.EntityList) error {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
	defer cancel()

	k, err := s.storageService.Add(ctx, el)
	if err != nil {
		return fmt.Errorf("hkp controller error: Add: %w", err)
	}

	_ = k
	// Send Verify mail
	// PS: Now verify false and you cant get key from DB

	return nil
}

func (s HkpController) Get(req *hkp.LookupRequest) (openpgp.EntityList, error) {

	req.Search = strings.Trim(req.Search, "0x")

	if len(req.Search) <= 15 {
		return nil, fmt.Errorf("controller error: Get: Low entropy string for search")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	k, err := s.storageService.Get(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("controller error: Get: %w", err)
	}

	return k, err
}

func (s HkpController) Index(req *hkp.LookupRequest) ([]hkp.IndexKey, error) {

	if len(req.Search) < 5 {
		return nil, fmt.Errorf("controller error: Index: short string for search")
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	k, err := s.storageService.Index(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("controller error: Get: %w", err)
	}

	return k, nil
}
