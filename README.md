# HKP-Clavis

HKP-Clavis was born out of a desire for simplicity. I found existing solutions like hkp-hagrid to be over-engineered and difficult to administer for smaller, focused deployments. My goal was to create a "minimally stable" implementation of an HKP server that does exactly what is needed—no more, no less—while maintaining high performance.

 - Note on Storage: During testing, it became clear that handling large keys (>2MB) directly in PostgreSQL isn't ideal. In the future, I plan to add S3/FileStorage support for blobs to keep the database lean and mean


## 🚀 Features

* **HKP Protocol Support**: Implements core `add`, `get`, and `index` operations.
* **High-Performance Architecture**: 
    * **Object Pooling**: Uses `sync.Pool` via a custom `KeyManager` to reuse `PGPKey` and `PGPUid` objects, significantly reducing GC pressure.
    * **Efficient Memory Allocation**: Controller and Service layers are built to minimize allocations during key parsing and transformation.
* **Database Optimization**: 
    * **PostgreSQL Backend**: Utilizes `pgx/v5` for robust connection pooling.
* **Security & Sanitization**: 
    * **Verification-Aware**: Only returns UIDs that have been marked as verified in the database.
    * **Key Sanitization**: Automatically filters out sensitive or unverified metadata before serving keys.

## 🛠 Tech Stack

* **Language**: Go 1.22+
* **Database**: PostgreSQL
* **Library**: `ProtonMail/go-crypto` (for OpenPGP operations)
* **Driver**: `pgx/v5`

## 📋 Backlog & Future Roadmap

The project is currently in a "feature freeze" for the core engine. The following features are planned for future development:

### 1. 🌐 GOTH Stack Web Interface
* **Frontend**: Implement a lightweight web UI using **Go Templates + HTMX** (The GOTH Stack).
* **Search**: A user-friendly search bar for finding keys without using the CLI.
* **Stats**: A dashboard showing server uptime, key count, and pool utilization metrics.
* **Kick GPG**: Debug. why key.openpgp.org server (hagrid) and clavis not work with `gpg --recv-key` T__T

### 2. 🗄️ Hybrid Storage & Large Payload Handling
* **Blob Storage Integration**: Implement an external Blob Storage (e.g., MinIO, S3, or local disk) for keys exceeding **1MB** in size to keep the PostgreSQL database lean.
* **Metadata/Binary Split**: Store key metadata in Postgres and the actual `.asc` packets in Blob storage.

### 3. 📧 Email Verification System
* **SMTP Service**: Activate the `SMTPPool` for sending verification emails.
* **Template Engine**: Support for both HTML and Plaintext email templates (required for classic PGP users).
* **Verification Route**: Implement the `GET /verify` endpoint to process tokens and update UID status.

### 4. 🛡️ System Hardening
* **Rate Limiting**: Add middleware to prevent brute-force key uploads or search "scraping".
* **SKS Peering**: Support for the synchronization protocol to federate with other global keyservers.

## ⚙️ Configuration

The application is configured via environment variables:

| Variable | Description |
| :--- | :--- |
| `LISTEN_ADDRESS` | Host to bind the server (e.g., `localhost`) |
| `LISTEN_PORT` | Port for the HKP service (e.g., `8181`) |
| `POSTGRES_USER` | Database user |
| `POSTGRES_PASSWORD` | Database password |
| `POSTGRES_ADDRESS` | Database host |
| `POSTGRES_PORT` | Database port |
| `POSTGRES_DATABASE` | Database name |
| `VERIFY_DEFAULT` | If `true`, new keys are marked as verified immediately (Dev mode) |

ps: verify by smtp not implemented `VERIFY_DEFAULT=true` is recommended

## 📦 Installation & Usage

```bash
# Build the binary
go build -o build/hkp-clavis internal/cmd/server/

# Run the server (ensure env vars are set)
./build/hkp-clavis
