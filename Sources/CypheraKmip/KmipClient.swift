//
// KmipClient.swift
// CypheraKmip
//
// KMIP client -- connects to any KMIP 1.4 server via mTLS.
// Full 27-operation support matching the Go reference.
//
// Usage:
//   let client = try KmipClient(
//       host: "kmip-server.corp.internal",
//       clientCert: "/path/to/client.pem",
//       clientKey: "/path/to/client-key.pem",
//       caCert: "/path/to/ca.pem"
//   )
//
//   let key = try client.fetchKey("my-key-name")
//   // key is Data of raw key bytes
//
//   client.close()
//

import Foundation

#if canImport(Security) && canImport(CFNetwork)
import Security
import CFNetwork
import CryptoKit

/// Maximum KMIP response size (16MB).
private let maxResponseSize = 16 * 1024 * 1024

/// Delegate for custom certificate validation.
///
/// Implementations can inspect the evaluated `SecTrust` and apply enterprise
/// PKI rules beyond the standard trust chain and pin checks. Returning `false`
/// causes the connection to fail with `KmipError.trustDelegateRejected`.
public protocol KmipClientTrustDelegate: AnyObject, Sendable {
    func client(_ client: KmipClient, shouldTrustCertificate trust: SecTrust) -> Bool
}

/// KMIP client with mTLS support.
///
/// Thread safety: the client serializes all network I/O and state mutation
/// behind an internal `NSLock`. Callers may share a single `KmipClient`
/// across threads or concurrency domains; individual operations run to
/// completion before another begins.
///
/// Available on macOS/iOS only (uses CFStream for TLS).
public final class KmipClient: @unchecked Sendable {
    public let host: String
    public let port: Int
    public let timeout: TimeInterval

    /// Optional SHA-256 digest of the leaf certificate's DER encoding.
    /// If set, the handshake is rejected unless the server's leaf cert
    /// digest matches exactly.
    public let pinnedCertificateSHA256: Data?

    /// Optional delegate for custom trust decisions (enterprise PKI etc.).
    public weak var trustDelegate: KmipClientTrustDelegate?

    #if DEBUG
    /// DEBUG-only: disables server certificate verification for local test rigs.
    /// This property does not exist in release builds and cannot be toggled in production.
    public let insecureSkipVerify: Bool
    #else
    /// Always false in release builds — retained for source compatibility.
    public var insecureSkipVerify: Bool { false }
    #endif

    private let clientCertPath: String
    private let clientKeyPath: String
    private let caCertPath: String?

    // All mutable state below is protected by `lock`.
    private let lock = NSLock()
    private var inputStream: InputStream?
    private var outputStream: OutputStream?
    private var isConnected = false

    #if DEBUG
    /// Initialize the KMIP client. (DEBUG builds accept `insecureSkipVerify`.)
    ///
    /// - Parameters:
    ///   - host: KMIP server hostname (non-empty).
    ///   - port: KMIP server port (default 5696, must be 1…65535).
    ///   - clientCert: Path to client certificate PEM file.
    ///   - clientKey: Path to client private key PEM file.
    ///   - caCert: Path to CA certificate PEM file (optional, uses system roots if not set).
    ///   - timeout: Connection timeout in seconds (default 10, must be > 0).
    ///   - pinnedCertificateSHA256: Optional SHA-256 digest of the leaf server
    ///     certificate's DER encoding. If set, connection fails unless the
    ///     server presents a matching leaf certificate.
    ///   - insecureSkipVerify: DEBUG-only: disables server certificate verification.
    ///     Emits a stderr warning when enabled. Not available in release builds.
    public init(
        host: String,
        clientCert: String,
        clientKey: String,
        port: Int = 5696,
        caCert: String? = nil,
        timeout: TimeInterval = 10,
        pinnedCertificateSHA256: Data? = nil,
        insecureSkipVerify: Bool = false
    ) throws {
        try KmipClient.validateInit(host: host, port: port, timeout: timeout,
                                    clientCert: clientCert, clientKey: clientKey)
        self.host = host
        self.port = port
        self.timeout = timeout
        self.insecureSkipVerify = insecureSkipVerify
        self.clientCertPath = clientCert
        self.clientKeyPath = clientKey
        self.caCertPath = caCert
        self.pinnedCertificateSHA256 = pinnedCertificateSHA256
        if insecureSkipVerify {
            FileHandle.standardError.write(Data(
                "CypheraKmip: WARNING — insecureSkipVerify=true. TLS certificate validation is DISABLED. DEBUG builds only.\n".utf8
            ))
        }
    }
    #else
    /// Initialize the KMIP client.
    ///
    /// - Parameters:
    ///   - host: KMIP server hostname (non-empty).
    ///   - port: KMIP server port (default 5696, must be 1…65535).
    ///   - clientCert: Path to client certificate PEM file.
    ///   - clientKey: Path to client private key PEM file.
    ///   - caCert: Path to CA certificate PEM file (optional, uses system roots if not set).
    ///   - timeout: Connection timeout in seconds (default 10, must be > 0).
    ///   - pinnedCertificateSHA256: Optional SHA-256 digest of the leaf server
    ///     certificate's DER encoding. If set, connection fails unless the
    ///     server presents a matching leaf certificate.
    public init(
        host: String,
        clientCert: String,
        clientKey: String,
        port: Int = 5696,
        caCert: String? = nil,
        timeout: TimeInterval = 10,
        pinnedCertificateSHA256: Data? = nil
    ) throws {
        try KmipClient.validateInit(host: host, port: port, timeout: timeout,
                                    clientCert: clientCert, clientKey: clientKey)
        self.host = host
        self.port = port
        self.timeout = timeout
        self.clientCertPath = clientCert
        self.clientKeyPath = clientKey
        self.caCertPath = caCert
        self.pinnedCertificateSHA256 = pinnedCertificateSHA256
    }
    #endif

    deinit {
        // Close without re-entering lock to keep deinit simple.
        inputStream?.close()
        outputStream?.close()
    }

    // MARK: - Validation

    private static func validateInit(
        host: String, port: Int, timeout: TimeInterval,
        clientCert: String, clientKey: String
    ) throws {
        guard !host.isEmpty else {
            throw KmipError.invalidParameter("host must not be empty")
        }
        guard port > 0, port <= 65535 else {
            throw KmipError.invalidParameter("port must be 1…65535, got \(port)")
        }
        guard timeout > 0 else {
            throw KmipError.invalidParameter("timeout must be positive, got \(timeout)")
        }
        guard !clientCert.isEmpty else {
            throw KmipError.invalidParameter("clientCert path must not be empty")
        }
        guard !clientKey.isEmpty else {
            throw KmipError.invalidParameter("clientKey path must not be empty")
        }
    }

    private static func requireNonEmpty(_ value: String, _ name: String) throws {
        guard !value.isEmpty else {
            throw KmipError.invalidParameter("\(name) must not be empty")
        }
    }

    private static func requirePositive<T: BinaryInteger>(_ value: T, _ name: String) throws {
        guard value > 0 else {
            throw KmipError.invalidParameter("\(name) must be positive, got \(value)")
        }
    }

    // MARK: - Core Operations (Create, Locate, Get, Activate, Destroy)

    /// Locate keys by name.
    public func locate(_ name: String) throws -> [String] {
        try KmipClient.requireNonEmpty(name, "name")
        let request = buildLocateRequest(name: name)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else { return [] }
        return parseLocatePayload(payload).uniqueIdentifiers
    }

    /// Get key material by unique ID.
    public func get(_ uniqueId: String) throws -> GetResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildGetRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return GetResult(objectType: nil, uniqueIdentifier: nil, keyMaterial: nil)
        }
        return autoreleasepool { parseGetPayload(payload) }
    }

    /// Get key material by unique ID, wrapped in `SecureKeyMaterial`.
    ///
    /// The returned container zeroes its backing buffer on `deinit`. Prefer
    /// this over `get(_:)` for callers that want bounded key lifetime.
    public func getSecure(_ uniqueId: String) throws -> SecureKeyMaterial {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildGetRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            throw KmipError.noKeyMaterial("KMIP: empty response payload for \(uniqueId)")
        }
        return try autoreleasepool { () throws -> SecureKeyMaterial in
            let result = parseGetPayload(payload)
            guard let material = result.keyMaterial else {
                throw KmipError.noKeyMaterial("KMIP: key \(uniqueId) has no extractable material")
            }
            return SecureKeyMaterial(material)
        }
    }

    /// Create a new symmetric key on the server.
    public func create(_ name: String, algorithm: UInt32 = KmipAlgorithm.AES, length: Int32 = 256) throws -> CreateResult {
        try KmipClient.requireNonEmpty(name, "name")
        try KmipClient.requirePositive(length, "length")
        let request = buildCreateRequest(name: name, algorithm: algorithm, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CreateResult(objectType: nil, uniqueIdentifier: nil)
        }
        return parseCreatePayload(payload)
    }

    /// Activate a key by unique ID.
    public func activate(_ uniqueId: String) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildActivateRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Destroy a key by unique ID.
    public func destroy(_ uniqueId: String) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildDestroyRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Convenience: locate by name + get material in one call.
    public func fetchKey(_ name: String) throws -> Data {
        try KmipClient.requireNonEmpty(name, "name")
        let ids = try locate(name)
        guard !ids.isEmpty else {
            throw KmipError.noKeyFound("KMIP: no key found with name \"\(name)\"")
        }
        let result = try get(ids[0])
        guard let material = result.keyMaterial else {
            throw KmipError.noKeyMaterial("KMIP: key \"\(name)\" (\(ids[0])) has no extractable material")
        }
        return material
    }

    /// Convenience: locate by name + get material in one call, wrapped in `SecureKeyMaterial`.
    public func fetchKeySecure(_ name: String) throws -> SecureKeyMaterial {
        try KmipClient.requireNonEmpty(name, "name")
        let ids = try locate(name)
        guard !ids.isEmpty else {
            throw KmipError.noKeyFound("KMIP: no key found with name \"\(name)\"")
        }
        return try getSecure(ids[0])
    }

    // MARK: - Key Pair Operations

    public func createKeyPair(_ name: String, algorithm: UInt32, length: Int32) throws -> CreateKeyPairResult {
        try KmipClient.requireNonEmpty(name, "name")
        try KmipClient.requirePositive(length, "length")
        let request = buildCreateKeyPairRequest(name: name, algorithm: algorithm, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CreateKeyPairResult(privateKeyUID: nil, publicKeyUID: nil)
        }
        return parseCreateKeyPairPayload(payload)
    }

    public func register(objectType: UInt32, material: Data, name: String, algorithm: UInt32, length: Int32) throws -> CreateResult {
        try KmipClient.requireNonEmpty(name, "name")
        try KmipClient.requirePositive(length, "length")
        guard !material.isEmpty else {
            throw KmipError.invalidParameter("material must not be empty")
        }
        let request = buildRegisterRequest(objectType: objectType, material: material, name: name, algorithm: algorithm, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CreateResult(objectType: nil, uniqueIdentifier: nil)
        }
        return parseCreatePayload(payload)
    }

    public func reKey(_ uniqueId: String) throws -> ReKeyResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildReKeyRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return ReKeyResult(uniqueIdentifier: nil)
        }
        return parseReKeyPayload(payload)
    }

    public func deriveKey(_ uniqueId: String, derivationData: Data, name: String, length: Int32) throws -> DeriveKeyResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        try KmipClient.requireNonEmpty(name, "name")
        try KmipClient.requirePositive(length, "length")
        guard !derivationData.isEmpty else {
            throw KmipError.invalidParameter("derivationData must not be empty")
        }
        let request = buildDeriveKeyRequest(uniqueId: uniqueId, derivationData: derivationData, name: name, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return DeriveKeyResult(uniqueIdentifier: nil)
        }
        return parseDeriveKeyPayload(payload)
    }

    // MARK: - Object Status Operations

    public func check(_ uniqueId: String) throws -> CheckResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildCheckRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CheckResult(uniqueIdentifier: nil)
        }
        return parseCheckPayload(payload)
    }

    // MARK: - Attribute Operations

    public func getAttributes(_ uniqueId: String) throws -> GetResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildGetAttributesRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return GetResult(objectType: nil, uniqueIdentifier: nil, keyMaterial: nil)
        }
        return parseGetPayload(payload)
    }

    public func getAttributeList(_ uniqueId: String) throws -> [String] {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildGetAttributeListRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else { return [] }
        let attrs = findChildren(payload, tag: Tag.AttributeName)
        return try attrs.map { item -> String in
            guard case .textString(let v) = item.value else {
                throw KmipError.unexpectedType(
                    "AttributeName expected textString, got type=\(item.type)")
            }
            return v
        }
    }

    public func addAttribute(_ uniqueId: String, name: String, value: String) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        try KmipClient.requireNonEmpty(name, "name")
        let request = buildAddAttributeRequest(uniqueId: uniqueId, attrName: name, attrValue: value)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    public func modifyAttribute(_ uniqueId: String, name: String, value: String) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        try KmipClient.requireNonEmpty(name, "name")
        let request = buildModifyAttributeRequest(uniqueId: uniqueId, attrName: name, attrValue: value)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    public func deleteAttribute(_ uniqueId: String, name: String) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        try KmipClient.requireNonEmpty(name, "name")
        let request = buildDeleteAttributeRequest(uniqueId: uniqueId, attrName: name)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    // MARK: - Lease Operations

    public func obtainLease(_ uniqueId: String) throws -> Int32 {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildObtainLeaseRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else { return 0 }
        if let lease = findChild(payload, tag: Tag.LeaseTime),
           case .integer(let v) = lease.value {
            return v
        }
        return 0
    }

    // MARK: - Lifecycle Operations

    public func revoke(_ uniqueId: String, reason: UInt32) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildRevokeRequest(uniqueId: uniqueId, reason: reason)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    public func archive(_ uniqueId: String) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildArchiveRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    public func recover(_ uniqueId: String) throws {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        let request = buildRecoverRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    // MARK: - Server Operations

    public func query() throws -> QueryResult {
        let request = buildQueryRequest()
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return QueryResult(operations: [], objectTypes: [])
        }
        return parseQueryPayload(payload)
    }

    public func poll() throws {
        let request = buildPollRequest()
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    public func discoverVersions() throws -> DiscoverVersionsResult {
        let request = buildDiscoverVersionsRequest()
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return DiscoverVersionsResult(versions: [])
        }
        return parseDiscoverVersionsPayload(payload)
    }

    // MARK: - Cryptographic Operations

    public func encrypt(_ uniqueId: String, data: Data) throws -> EncryptResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        guard !data.isEmpty else {
            throw KmipError.invalidParameter("data must not be empty")
        }
        let request = buildEncryptRequest(uniqueId: uniqueId, data: data)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return EncryptResult(data: nil, nonce: nil)
        }
        return parseEncryptPayload(payload)
    }

    public func decrypt(_ uniqueId: String, data: Data, nonce: Data? = nil) throws -> DecryptResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        guard !data.isEmpty else {
            throw KmipError.invalidParameter("data must not be empty")
        }
        let request = buildDecryptRequest(uniqueId: uniqueId, data: data, nonce: nonce)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return DecryptResult(data: nil)
        }
        return parseDecryptPayload(payload)
    }

    public func sign(_ uniqueId: String, data: Data) throws -> SignResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        guard !data.isEmpty else {
            throw KmipError.invalidParameter("data must not be empty")
        }
        let request = buildSignRequest(uniqueId: uniqueId, data: data)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return SignResult(signatureData: nil)
        }
        return parseSignPayload(payload)
    }

    public func signatureVerify(_ uniqueId: String, data: Data, signature: Data) throws -> SignatureVerifyResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        guard !data.isEmpty else {
            throw KmipError.invalidParameter("data must not be empty")
        }
        guard !signature.isEmpty else {
            throw KmipError.invalidParameter("signature must not be empty")
        }
        let request = buildSignatureVerifyRequest(uniqueId: uniqueId, data: data, signature: signature)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return SignatureVerifyResult(valid: false)
        }
        return parseSignatureVerifyPayload(payload)
    }

    public func mac(_ uniqueId: String, data: Data) throws -> MACResult {
        try KmipClient.requireNonEmpty(uniqueId, "uniqueId")
        guard !data.isEmpty else {
            throw KmipError.invalidParameter("data must not be empty")
        }
        let request = buildMACRequest(uniqueId: uniqueId, data: data)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return MACResult(macData: nil)
        }
        return parseMACPayload(payload)
    }

    // MARK: - Connection Management

    /// Close the TLS connection.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        closeLocked()
    }

    private func closeLocked() {
        inputStream?.close()
        outputStream?.close()
        inputStream = nil
        outputStream = nil
        isConnected = false
    }

    // MARK: - Private

    private func send(_ request: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        try connectLocked()

        guard let output = outputStream else {
            throw KmipError.connectionFailed("No output stream")
        }

        // Write request
        let written = request.withUnsafeBytes { ptr -> Int in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return output.write(base, maxLength: request.count)
        }
        guard written == request.count else {
            closeLocked()
            throw KmipError.connectionFailed("Failed to write request")
        }

        // Read TTLV header (8 bytes) to determine total length
        let header: Data
        do {
            header = try recvExactLocked(8)
        } catch {
            closeLocked()
            throw error
        }

        let valueLength = Int(
            (UInt32(header[4]) << 24) |
            (UInt32(header[5]) << 16) |
            (UInt32(header[6]) << 8) |
            UInt32(header[7])
        )

        // Validate response size before allocating.
        if valueLength > maxResponseSize {
            closeLocked()
            throw KmipError.connectionFailed(
                "KMIP: response too large (\(valueLength) bytes, max \(maxResponseSize))")
        }

        let body: Data
        do {
            body = try recvExactLocked(valueLength)
        } catch {
            closeLocked()
            throw error
        }

        return header + body
    }

    private func recvExactLocked(_ n: Int) throws -> Data {
        guard let input = inputStream else {
            throw KmipError.connectionFailed("No input stream")
        }

        var data = Data()
        var remaining = n
        let bufSize = 4096
        var buf = [UInt8](repeating: 0, count: bufSize)

        while remaining > 0 {
            let toRead = min(remaining, bufSize)
            let read = input.read(&buf, maxLength: toRead)
            guard read > 0 else {
                throw KmipError.connectionFailed("Connection closed unexpectedly")
            }
            data.append(buf, count: read)
            remaining -= read
        }

        return data
    }

    private func connectLocked() throws {
        guard !isConnected else { return }

        var readStream: Unmanaged<CFReadStream>?
        var writeStream: Unmanaged<CFWriteStream>?

        CFStreamCreatePairWithSocketToHost(
            nil,
            host as CFString,
            UInt32(port),
            &readStream,
            &writeStream
        )

        guard let input = readStream?.takeRetainedValue() as InputStream?,
              let output = writeStream?.takeRetainedValue() as OutputStream? else {
            throw KmipError.connectionFailed("Failed to create streams")
        }

        // Configure TLS -- always verify certificates by default (uses system roots).
        var sslSettings: [String: Any] = [
            kCFStreamSSLLevel as String: kCFStreamSocketSecurityLevelNegotiatedSSL,
            kCFStreamSSLPeerName as String: host,
        ]

        #if DEBUG
        if insecureSkipVerify {
            sslSettings[kCFStreamSSLValidatesCertificateChain as String] = false
        }
        #endif

        input.setProperty(sslSettings, forKey: .init(kCFStreamPropertySSLSettings as String))
        output.setProperty(sslSettings, forKey: .init(kCFStreamPropertySSLSettings as String))

        input.open()
        output.open()

        self.inputStream = input
        self.outputStream = output
        self.isConnected = true

        // Wait for handshake and validate the peer trust. If validation fails
        // we close the connection so no application data is transmitted.
        do {
            try validateTrustLocked()
        } catch {
            closeLocked()
            throw error
        }
    }

    /// Full `SecTrust` evaluation with optional pinning and delegate hook.
    /// Runs after CFStream completes the TLS handshake and before any
    /// application bytes are written.
    private func validateTrustLocked() throws {
        #if DEBUG
        if insecureSkipVerify { return }
        #endif

        guard let output = outputStream, let input = inputStream else {
            throw KmipError.tlsValidationFailed("streams unavailable")
        }

        // Wait for handshake completion. CFStream signals `hasSpaceAvailable`
        // on the write stream once the TLS handshake has finished and it can
        // accept application data. Poll until available or timeout.
        let deadline = Date().addingTimeInterval(timeout)
        while !output.hasSpaceAvailable {
            if let err = output.streamError {
                throw KmipError.tlsValidationFailed("stream error during handshake: \(err)")
            }
            if Date() >= deadline {
                throw KmipError.tlsValidationFailed("TLS handshake timeout after \(timeout)s")
            }
            Thread.sleep(forTimeInterval: 0.01)
        }

        // Peer trust is surfaced on the input stream post-handshake.
        guard let trustProp = input.property(forKey: .init(kCFStreamPropertySSLPeerTrust as String)),
              CFGetTypeID(trustProp as CFTypeRef) == SecTrustGetTypeID() else {
            throw KmipError.tlsValidationFailed("peer trust unavailable after handshake")
        }
        // swiftlint:disable:next force_cast
        let trust = trustProp as! SecTrust

        // Apply a standard SSL policy with hostname verification.
        let policy = SecPolicyCreateSSL(true, host as CFString)
        let policyStatus = SecTrustSetPolicies(trust, policy)
        guard policyStatus == errSecSuccess else {
            throw KmipError.tlsValidationFailed("SecTrustSetPolicies failed (\(policyStatus))")
        }

        var cfError: CFError?
        let ok = SecTrustEvaluateWithError(trust, &cfError)
        guard ok else {
            let desc = cfError.map { CFErrorCopyDescription($0) as String } ?? "trust evaluation failed"
            throw KmipError.tlsValidationFailed(desc)
        }

        // Pin check (H5).
        if let pin = pinnedCertificateSHA256 {
            guard let leaf = leafCertificate(from: trust) else {
                throw KmipError.tlsValidationFailed("no leaf certificate available for pin check")
            }
            let der = SecCertificateCopyData(leaf) as Data
            let digest = Data(SHA256.hash(data: der))
            guard digest == pin else {
                throw KmipError.certificatePinMismatch
            }
        }

        // Delegate hook (H6).
        if let delegate = trustDelegate,
           !delegate.client(self, shouldTrustCertificate: trust) {
            throw KmipError.trustDelegateRejected
        }
    }

    /// Best-effort extraction of the leaf certificate across OS versions.
    private func leafCertificate(from trust: SecTrust) -> SecCertificate? {
        if #available(macOS 12.0, iOS 15.0, tvOS 15.0, watchOS 8.0, *) {
            guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let first = chain.first else {
                return nil
            }
            return first
        } else {
            // SecTrustGetCertificateAtIndex is available on macOS 10.15 / iOS 13.
            // Deprecated on newer OSes but the fallback path is only hit below the cutoff.
            #if !(swift(>=5.9) && (os(macOS) || os(iOS)))
            return nil
            #else
            let count = SecTrustGetCertificateCount(trust)
            guard count > 0 else { return nil }
            return SecTrustGetCertificateAtIndex(trust, 0)
            #endif
        }
    }
}

// MARK: - Async API (M7)

extension KmipClient {
    public func locate(_ name: String) async throws -> [String] {
        try await runDetached { try self.locate(name) }
    }

    public func get(_ uniqueId: String) async throws -> GetResult {
        try await runDetached { try self.get(uniqueId) }
    }

    public func getSecure(_ uniqueId: String) async throws -> SecureKeyMaterial {
        try await runDetached { try self.getSecure(uniqueId) }
    }

    public func create(_ name: String, algorithm: UInt32 = KmipAlgorithm.AES, length: Int32 = 256) async throws -> CreateResult {
        try await runDetached { try self.create(name, algorithm: algorithm, length: length) }
    }

    public func activate(_ uniqueId: String) async throws {
        try await runDetached { try self.activate(uniqueId) }
    }

    public func destroy(_ uniqueId: String) async throws {
        try await runDetached { try self.destroy(uniqueId) }
    }

    public func fetchKey(_ name: String) async throws -> Data {
        try await runDetached { try self.fetchKey(name) }
    }

    public func fetchKeySecure(_ name: String) async throws -> SecureKeyMaterial {
        try await runDetached { try self.fetchKeySecure(name) }
    }

    public func encrypt(_ uniqueId: String, data: Data) async throws -> EncryptResult {
        try await runDetached { try self.encrypt(uniqueId, data: data) }
    }

    public func decrypt(_ uniqueId: String, data: Data, nonce: Data? = nil) async throws -> DecryptResult {
        try await runDetached { try self.decrypt(uniqueId, data: data, nonce: nonce) }
    }

    public func sign(_ uniqueId: String, data: Data) async throws -> SignResult {
        try await runDetached { try self.sign(uniqueId, data: data) }
    }

    public func signatureVerify(_ uniqueId: String, data: Data, signature: Data) async throws -> SignatureVerifyResult {
        try await runDetached { try self.signatureVerify(uniqueId, data: data, signature: signature) }
    }

    public func mac(_ uniqueId: String, data: Data) async throws -> MACResult {
        try await runDetached { try self.mac(uniqueId, data: data) }
    }

    public func query() async throws -> QueryResult {
        try await runDetached { try self.query() }
    }

    public func discoverVersions() async throws -> DiscoverVersionsResult {
        try await runDetached { try self.discoverVersions() }
    }

    /// Detach the synchronous call onto a background thread so that callers
    /// in Swift structured concurrency do not stall the cooperative pool.
    private func runDetached<T: Sendable>(_ body: @Sendable @escaping () throws -> T) async throws -> T {
        try await Task.detached(priority: .userInitiated) {
            try body()
        }.value
    }
}

#endif // canImport(Security) && canImport(CFNetwork)
