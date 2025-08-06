## Key storage

```
| fingerprint string | keyring |
```

## Verify

Verify uri `/pks/v/{fingerprint}/{email}/{token}`

Verify pipe::> [!WARNING]
- User send key to server
- If key new in server 
  - Send Message to emails in uids with token

TODO: Clear keys with unverify uids

UID Verify Table

```
| fingerprint string | uid string | email string | verify_token string | verify bool |
```

- uid "Full Name (comment) <email@example.com>"
- email email@example.com

## Get key

URI `/pks/lookup?op={op}&search={search}`

### Sanitaze key

Key max-size

#### Sanitaze key and cache it

Before send key we can verify all signatures in our server

And send key with self-storade key only 

It can so slow and loading our database.

Before sanitaze we can look on

PGP entity.SelfSignature.CreationTime

If time < cached_time
- Use cache
Else
- Put verify state uids of fingerprints of signatures on getting key

// PGP entity.Identities[0].Signatures[0].CreationTime


