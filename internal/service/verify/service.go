package mail

import (
	"context"
	"hkp-clavis/internal/model"
)

type VerifyServiceInterface interface {
	SendVerifyMessage(ctx context.Context, el []*model.PGPKey) error
}
