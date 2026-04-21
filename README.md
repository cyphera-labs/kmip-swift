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

let client = try KmipClient(
    host: "kmip-server.corp.internal",
    clientCert: "/path/to/client.pem",
    clientKey: "/path/to/client-key.pem",
    caCert: "/path/to/ca.pem"
)

// Fetch a key by name (locate + get in one call).
// Prefer `fetchKeySecure` — it wraps bytes in a SecureKeyMaterial that
// zeroes its backing buffer on deinit.
let secure = try client.fetchKeySecure("my-encryption-key")
try secure.withBytes { data in
    // use `data` inside this closure — do not escape it.
}

// Or step by step:
let ids = try client.locate("my-key")
let secureById = try client.getSecure(ids[0])
secureById.withBytes { _ in /* use bytes */ }

// Create a new AES-256 key on the server
let created = try client.create("new-key-name")
print(created.uniqueIdentifier!)

client.close()
```

### Async

All I/O methods have async overloads for use inside structured concurrency:

```swift
let key = try await client.fetchKeySecure("my-encryption-key")
let result = try await client.create("new-key-name")
```

### Certificate pinning and custom trust

```swift
// Pin the leaf certificate's DER SHA-256 digest.
let pin = Data(/* 32 bytes */)
let client = try KmipClient(
    host: "kmip.example.com",
    clientCert: "/path/to/client.pem",
    clientKey: "/path/to/client-key.pem",
    pinnedCertificateSHA256: pin
)

// Or install a delegate for enterprise PKI logic.
final class MyTrust: KmipClientTrustDelegate {
    func client(_ client: KmipClient, shouldTrustCertificate trust: SecTrust) -> Bool {
        // inspect `trust` and return a decision
        return true
    }
}
client.trustDelegate = MyTrust()
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

Certificate chain validation is always performed via `SecTrustEvaluateWithError`
with a standard SSL policy (including hostname verification). `insecureSkipVerify`
exists only in **DEBUG** builds and emits a stderr warning when enabled — it is
not part of the release API surface.

## App Transport Security (iOS / macOS apps)

KMIP connections use TLS via `CFStream`. If the host app disables App Transport
Security globally (`NSAllowsArbitraryLoads = YES`), platform-level enforcement
is weakened for all other network traffic. Recommended `Info.plist` entries for
apps embedding `kmip-swift`:

```xml
<key>NSAppTransportSecurity</key>
<dict>
  <!-- Keep ATS enforcement for all default connections. -->
  <key>NSAllowsArbitraryLoads</key>
  <false/>
  <!-- If you must reach a KMIP server on a non-public hostname, scope
       the exception to that host only. -->
  <key>NSExceptionDomains</key>
  <dict>
    <key>kmip.internal</key>
    <dict>
      <key>NSExceptionRequiresForwardSecrecy</key>
      <true/>
      <key>NSExceptionMinimumTLSVersion</key>
      <string>TLSv1.2</string>
    </dict>
  </dict>
</dict>
```

Avoid `NSAllowsArbitraryLoads = YES` for the whole app. Prefer per-domain
exceptions and combine them with `pinnedCertificateSHA256` for defense in depth.

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
