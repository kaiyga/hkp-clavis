package model

import "sync"

var pgpKeyPool = sync.Pool{
	New: func() any {
		return &PGPKey{
			Uids: make([]*PGPUid, 0, 10),
		}
	},
}
var pgpUidPool = sync.Pool{
	New: func() any {
		return &PGPUid{}
	},
}

// Struct for managed keys allocation in memory
type KeyManager struct{}

func NewKeyManager() *KeyManager {
	return &KeyManager{}
}

func (m *KeyManager) Get() *PGPKey {
	k := pgpKeyPool.Get().(*PGPKey)
	k.Reset()
	return k
}
func (m *KeyManager) GetUid() *PGPUid {
	u := pgpUidPool.Get().(*PGPUid)
	u.Reset()
	return u
}

func (m *KeyManager) ReleaseUid(u ...*PGPUid) {
	for _, u := range u {
		if u == nil {
			continue
		}
		pgpUidPool.Put(u)
	}
}

func (m *KeyManager) Release(keys ...*PGPKey) {
	for _, k := range keys {
		if k == nil {
			continue
		}
		m.ReleaseUid(k.Uids...)
		// Unlink all uids objects
		k.Uids = k.Uids[:0]
		pgpKeyPool.Put(k)
	}
}

func (m *KeyManager) ReleaseSlice(keys []*PGPKey) {
	m.Release(keys...)
}
