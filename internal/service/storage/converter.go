package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
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

// ConverterPgpToService converts a raw openpgp.EntityList into a slice of service.PGPkey objects.
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
func ConverterPgpToService(entities openpgp.EntityList) ([]*PGPkey, error) {
	var pgpKeys []*PGPkey

	if entities == nil {
		return pgpKeys, nil
	}

	for i, entity := range entities {
		// Test on correct data
		if entity == nil {
			log.Printf("Warning: ConverterPgpToService: encountered nil entity at index %d, skipping.", i)
			continue
		}
		if entity.PrimaryKey == nil {
			log.Printf("Warning: ConverterPgpToService: entity at index %d has no primary key, skipping.", i)
			continue
		}

		publicKeyBuf := bytes.NewBuffer(nil)
		publicKeyWriter, err := armor.Encode(publicKeyBuf, openpgp.PublicKeyType, nil)
		if err != nil {
			return nil, fmt.Errorf("converter error: entity %d: failed to create armor encoder: %w", i, err)
		}

		if err = entity.Serialize(publicKeyWriter); err != nil {
			return nil, fmt.Errorf("converter error: entity %d: failed to serialize public key: %w", i, err)
		}
		publicKeyWriter.Close()

		// Write it

		pgpKey := PGPkey{
			Revoked:     entity.Revoked(time.Now()),
			UpdateTime:  entity.PrimaryKey.CreationTime.UTC(), // <--- FIX IS HERE! Use PrimaryKey's CreationTime
			Fingerprint: strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)),
			Packet:      publicKeyBuf.String(),
			Uids:        []*PGPUid{},
		}

		// Process each UID for the current entity
		for _, uid := range entity.Identities {
			if uid == nil || uid.UserId == nil {
				log.Printf("Warning: ConverterPgpToService: encountered nil Identity or UserId for key %s, skipping.", pgpKey.Fingerprint)
				continue
			}
			if uid.Name == "" {
				log.Printf("Warning: ConverterPgpToService: encountered empty User ID string for key %s, skipping.", pgpKey.Fingerprint)
				continue
			}

			randBytes := make([]byte, 16)
			if _, err := rand.Read(randBytes); err != nil {
				return nil, fmt.Errorf("converter error: key %s: failed to generate random bytes for token: %w", pgpKey.Fingerprint, err)
			}
			token := hex.EncodeToString(randBytes)

			extractedEmail := extractEmail(uid.Name)
			if extractedEmail == "" {
				log.Printf("Warning: ConverterPgpToService: extracted empty email from UID '%s' for key %s, skipping UID.", uid.Name, pgpKey.Fingerprint)
				continue
			}

			pgpKey.Uids = append(pgpKey.Uids, &PGPUid{
				Verify:       false,
				UIDString:    uid.Name,
				Email:        extractedEmail,
				Token:        token,
				TokenExpires: time.Now().Add(time.Hour * 5),
				Fingerprint:  pgpKey.Fingerprint,
			})
		}
		pgpKeys = append(pgpKeys, &pgpKey)
	}
	return pgpKeys, nil
}
