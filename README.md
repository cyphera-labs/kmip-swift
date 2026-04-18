# kmip-swift

[![CI](https://github.com/cyphera-labs/kmip-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-swift/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-swift/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-swift/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for Swift -- connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```swift
// Package.swift
.package(url: "https://github.com/cyphera-labs/kmip-swift", from: "0.1.0")
```

## Quick Start

```swift
import CypheraKmip

let client = KmipClient(
    host: "kmip-server.corp.internal",
    clientCert: "/path/to/client.pem",
    clientKey: "/path/to/client-key.pem",
    caCert: "/path/to/ca.pem"
)

// Fetch a key by name (locate + get in one call)
let key = try client.fetchKey("my-encryption-key")
// key is Data of raw key bytes (e.g., 32 bytes for AES-256)

// Or step by step:
let ids = try client.locate("my-key")
let result = try client.get(ids[0])
print(result.keyMaterial!)  // Data

// Create a new AES-256 key on the server
let created = try client.create("new-key-name")
print(created.uniqueIdentifier!)

client.close()
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `client.locate(name)` | Find keys by name, returns unique IDs |
| Get | `client.get(id)` | Fetch key material by unique ID |
| Create | `client.create(name, algo, length)` | Create a new symmetric key |
| Fetch | `client.fetchKey(name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** -- identifies your application to the KMS
- **Client private key** -- proves ownership of the certificate
- **CA certificate** -- validates the KMS server's certificate

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero Dependencies

This library uses only Swift standard library and Foundation. No external dependencies.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 -- Copyright 2026 Horizon Digital Engineering LLC
