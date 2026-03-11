package model

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func extractEmail(fullNameWithEmail string) string {
	re := regexp.MustCompile(`<([^>]+)>`)
	matches := re.FindStringSubmatch(fullNameWithEmail)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

var (
	bufferPool = sync.Pool{
		New: func() any { return new(bytes.Buffer) },
	}
)

// ConverterPgpToService converts a raw openpgp.EntityList into a slice of PGPkey objects.
// It parses key data, generates verification tokens for UIDs, and extracts email addresses.
//
// Parameters:
//
//	entities: The openpgp.EntityList obtained from parsing an armored PGP block.
//
// Returns:
//
//	[]*PGPkey: A slice of converted PGPkey objects. Returns an empty (non-nil) slice if no valid entities are found.
//	error: An error if any entity fails to be processed or contains invalid data.
func (m *KeyManager) ConverterPgpToService(entities openpgp.EntityList, defaultVerifyValue bool) ([]*PGPKey, func(), error) {
	res := make([]*PGPKey, 0, len(entities))
	release := func() {
		m.ReleaseSlice(res)
	}

	for _, entity := range entities {
		if entity == nil || entity.PrimaryKey == nil {
			continue
		}

		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()

		publicKeyWriter, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
		if err != nil {
			bufferPool.Put(buf)
			return nil, release, fmt.Errorf("armor encode error: %w", err)
		}

		if err := entity.Serialize(publicKeyWriter); err != nil {
			publicKeyWriter.Close()
			bufferPool.Put(buf)
			return nil, release, fmt.Errorf("serialize error: %w", err)
		}
		publicKeyWriter.Close()

		pgpKey := pgpKeyPool.Get().(*PGPKey)
		pgpKey.Reset()

		pgpKey.Fingerprint = strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
		pgpKey.Packet = buf.String()
		pgpKey.UpdateTime = entity.PrimaryKey.CreationTime.UTC()
		pgpKey.Revoked = entity.Revoked(time.Now())

		bufferPool.Put(buf)

		for _, identity := range entity.Identities {
			if identity == nil || identity.UserId == nil || identity.Name == "" {
				continue
			}

			extractedEmail := extractEmail(identity.Name)
			if extractedEmail == "" {
				log.Printf("Warning: no email in UID %s for key %s", identity.Name, pgpKey.Fingerprint)
				continue
			}

			var tokenRaw [16]byte
			if _, err := rand.Read(tokenRaw[:]); err != nil {
				return nil, release, fmt.Errorf("token gen error: %w", err)
			}
			token := hex.EncodeToString(tokenRaw[:])

			pgpKey.Uids = append(pgpKey.Uids, &PGPUid{
				Verify:       defaultVerifyValue,
				UIDString:    identity.Name,
				Email:        extractedEmail,
				Token:        token,
				TokenExpires: time.Now().Add(time.Hour * 5),
				Fingerprint:  pgpKey.Fingerprint,
			})
		}

		res = append(res, pgpKey)
	}

	return res, release, nil
}

func SanitizeAndFilterKey(dbKey *PGPKey) (openpgp.EntityList, error) {

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
