package storage

import (
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

type StorageInterface interface {
	AddKey(openpgp.EntityList) error
	GetKeyByUID(uid string) openpgp.EntityList
	GetKeyByFingerprint(fngr string) openpgp.EntityList
}

type PGPkey struct {
	Revoked     bool
	UpdateTime  time.Time
	Fingerprint string
	Packet      string
	Uids        []*PGPUid
}

type PGPUid struct {
	Verify       bool
	Token        string
	TokenExpires time.Time
	Email        string
	UIDString    string // "Full Name (comment) <email@example.com>"
	Fingerprint  string
}
