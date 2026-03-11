package serv

import (
	"context"
	"hkp-clavis/internal/model"
	service "hkp-clavis/internal/service/verify"
)

type VerifyMailService struct {
	service.VerifyServiceInterface
}

func (s VerifyMailService) SendVerifyMessage(ctx context.Context, el []*model.PGPKey) error {
	return nil
}
