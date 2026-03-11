package model

import "time"

type PGPKey struct {
	Revoked     bool
	UpdateTime  time.Time
	Fingerprint string
	Packet      string
	Uids        []*PGPUid
}

// Clear data from object
func (k *PGPKey) Reset() {
	k.Fingerprint = ""
	k.Packet = ""
	k.Revoked = false
	k.Uids = k.Uids[:0]
}

type PGPUid struct {
	Verify       bool
	Token        string
	TokenExpires time.Time
	Email        string
	UIDString    string // "Full Name (comment) <email@example.com>"
	Fingerprint  string
}

func (u *PGPUid) Reset() {
	u.Verify = false
	u.Token = ""
	u.TokenExpires = time.Time{}
	u.Email = ""
	u.UIDString = ""
	u.Fingerprint = ""
}
