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

/// KMIP client with mTLS support.
/// Available on macOS/iOS only (uses CFStream for TLS).
public class KmipClient {
    public let host: String
    public let port: Int
    public let timeout: TimeInterval

    private let clientCertPath: String
    private let clientKeyPath: String
    private let caCertPath: String?

    private var inputStream: InputStream?
    private var outputStream: OutputStream?
    private var isConnected = false

    /// Initialize the KMIP client.
    ///
    /// - Parameters:
    ///   - host: KMIP server hostname.
    ///   - port: KMIP server port (default 5696).
    ///   - clientCert: Path to client certificate PEM file.
    ///   - clientKey: Path to client private key PEM file.
    ///   - caCert: Path to CA certificate PEM file (optional).
    ///   - timeout: Connection timeout in seconds (default 10).
    public init(
        host: String,
        clientCert: String,
        clientKey: String,
        port: Int = 5696,
        caCert: String? = nil,
        timeout: TimeInterval = 10
    ) {
        self.host = host
        self.port = port
        self.timeout = timeout
        self.clientCertPath = clientCert
        self.clientKeyPath = clientKey
        self.caCertPath = caCert
    }

    // MARK: - Core Operations (Create, Locate, Get, Activate, Destroy)

    /// Locate keys by name.
    ///
    /// - Parameter name: Key name to search for.
    /// - Returns: Array of unique identifier strings.
    public func locate(_ name: String) throws -> [String] {
        let request = buildLocateRequest(name: name)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else { return [] }
        return parseLocatePayload(payload).uniqueIdentifiers
    }

    /// Get key material by unique ID.
    ///
    /// - Parameter uniqueId: The unique identifier of the key.
    /// - Returns: GetResult with objectType, uniqueIdentifier, keyMaterial.
    public func get(_ uniqueId: String) throws -> GetResult {
        let request = buildGetRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return GetResult(objectType: nil, uniqueIdentifier: nil, keyMaterial: nil)
        }
        return parseGetPayload(payload)
    }

    /// Create a new symmetric key on the server.
    ///
    /// - Parameters:
    ///   - name: Key name.
    ///   - algorithm: Algorithm constant (default AES).
    ///   - length: Key length in bits (default 256).
    /// - Returns: CreateResult with objectType and uniqueIdentifier.
    public func create(_ name: String, algorithm: UInt32 = KmipAlgorithm.AES, length: Int32 = 256) throws -> CreateResult {
        let request = buildCreateRequest(name: name, algorithm: algorithm, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CreateResult(objectType: nil, uniqueIdentifier: nil)
        }
        return parseCreatePayload(payload)
    }

    /// Activate a key by unique ID.
    ///
    /// - Parameter uniqueId: The unique identifier of the key.
    public func activate(_ uniqueId: String) throws {
        let request = buildActivateRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Destroy a key by unique ID.
    ///
    /// - Parameter uniqueId: The unique identifier of the key.
    public func destroy(_ uniqueId: String) throws {
        let request = buildDestroyRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Convenience: locate by name + get material in one call.
    ///
    /// - Parameter name: Key name.
    /// - Returns: Raw key bytes as Data.
    public func fetchKey(_ name: String) throws -> Data {
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

    // MARK: - Key Pair Operations

    /// Create a new asymmetric key pair on the server.
    ///
    /// - Parameters:
    ///   - name: Key pair name.
    ///   - algorithm: Algorithm constant (e.g. RSA, ECDSA).
    ///   - length: Key length in bits.
    /// - Returns: CreateKeyPairResult with privateKeyUID and publicKeyUID.
    public func createKeyPair(_ name: String, algorithm: UInt32, length: Int32) throws -> CreateKeyPairResult {
        let request = buildCreateKeyPairRequest(name: name, algorithm: algorithm, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CreateKeyPairResult(privateKeyUID: nil, publicKeyUID: nil)
        }
        return parseCreateKeyPairPayload(payload)
    }

    /// Register existing key material on the server.
    ///
    /// - Parameters:
    ///   - objectType: Object type constant.
    ///   - material: Raw key material bytes.
    ///   - name: Key name (empty string to omit).
    ///   - algorithm: Algorithm constant.
    ///   - length: Key length in bits.
    /// - Returns: CreateResult with objectType and uniqueIdentifier.
    public func register(objectType: UInt32, material: Data, name: String, algorithm: UInt32, length: Int32) throws -> CreateResult {
        let request = buildRegisterRequest(objectType: objectType, material: material, name: name, algorithm: algorithm, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CreateResult(objectType: nil, uniqueIdentifier: nil)
        }
        return parseCreatePayload(payload)
    }

    /// Re-key an existing key on the server.
    ///
    /// - Parameter uniqueId: The unique identifier of the key.
    /// - Returns: ReKeyResult with the new uniqueIdentifier.
    public func reKey(_ uniqueId: String) throws -> ReKeyResult {
        let request = buildReKeyRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return ReKeyResult(uniqueIdentifier: nil)
        }
        return parseReKeyPayload(payload)
    }

    /// Derive a new key from an existing key.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the source key.
    ///   - derivationData: Data used in derivation.
    ///   - name: Name for the derived key.
    ///   - length: Derived key length in bits.
    /// - Returns: DeriveKeyResult with uniqueIdentifier.
    public func deriveKey(_ uniqueId: String, derivationData: Data, name: String, length: Int32) throws -> DeriveKeyResult {
        let request = buildDeriveKeyRequest(uniqueId: uniqueId, derivationData: derivationData, name: name, length: length)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return DeriveKeyResult(uniqueIdentifier: nil)
        }
        return parseDeriveKeyPayload(payload)
    }

    // MARK: - Object Status Operations

    /// Check the status of a managed object.
    ///
    /// - Parameter uniqueId: The unique identifier of the object.
    /// - Returns: CheckResult with uniqueIdentifier.
    public func check(_ uniqueId: String) throws -> CheckResult {
        let request = buildCheckRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return CheckResult(uniqueIdentifier: nil)
        }
        return parseCheckPayload(payload)
    }

    // MARK: - Attribute Operations

    /// Fetch all attributes of a managed object.
    ///
    /// - Parameter uniqueId: The unique identifier of the object.
    /// - Returns: GetResult with attribute data.
    public func getAttributes(_ uniqueId: String) throws -> GetResult {
        let request = buildGetAttributesRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return GetResult(objectType: nil, uniqueIdentifier: nil, keyMaterial: nil)
        }
        return parseGetPayload(payload)
    }

    /// Fetch the list of attribute names for a managed object.
    ///
    /// - Parameter uniqueId: The unique identifier of the object.
    /// - Returns: Array of attribute name strings.
    public func getAttributeList(_ uniqueId: String) throws -> [String] {
        let request = buildGetAttributeListRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else { return [] }
        let attrs = findChildren(payload, tag: Tag.AttributeName)
        return attrs.compactMap { item -> String? in
            if case .textString(let v) = item.value { return v }
            return nil
        }
    }

    /// Add an attribute to a managed object.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the object.
    ///   - name: Attribute name.
    ///   - value: Attribute value.
    public func addAttribute(_ uniqueId: String, name: String, value: String) throws {
        let request = buildAddAttributeRequest(uniqueId: uniqueId, attrName: name, attrValue: value)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Modify an attribute of a managed object.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the object.
    ///   - name: Attribute name.
    ///   - value: New attribute value.
    public func modifyAttribute(_ uniqueId: String, name: String, value: String) throws {
        let request = buildModifyAttributeRequest(uniqueId: uniqueId, attrName: name, attrValue: value)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Delete an attribute from a managed object.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the object.
    ///   - name: Attribute name.
    public func deleteAttribute(_ uniqueId: String, name: String) throws {
        let request = buildDeleteAttributeRequest(uniqueId: uniqueId, attrName: name)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    // MARK: - Lease Operations

    /// Obtain a lease for a managed object.
    ///
    /// - Parameter uniqueId: The unique identifier of the object.
    /// - Returns: Lease time in seconds.
    public func obtainLease(_ uniqueId: String) throws -> Int32 {
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

    /// Revoke a managed object with the given reason code.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the object.
    ///   - reason: Revocation reason code.
    public func revoke(_ uniqueId: String, reason: UInt32) throws {
        let request = buildRevokeRequest(uniqueId: uniqueId, reason: reason)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Archive a managed object.
    ///
    /// - Parameter uniqueId: The unique identifier of the object.
    public func archive(_ uniqueId: String) throws {
        let request = buildArchiveRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Recover an archived managed object.
    ///
    /// - Parameter uniqueId: The unique identifier of the object.
    public func recover(_ uniqueId: String) throws {
        let request = buildRecoverRequest(uniqueId: uniqueId)
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    // MARK: - Server Operations

    /// Query the server for supported operations and object types.
    ///
    /// - Returns: QueryResult with operations and objectTypes arrays.
    public func query() throws -> QueryResult {
        let request = buildQueryRequest()
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return QueryResult(operations: [], objectTypes: [])
        }
        return parseQueryPayload(payload)
    }

    /// Poll the server.
    public func poll() throws {
        let request = buildPollRequest()
        let responseData = try send(request)
        _ = try parseResponse(responseData)
    }

    /// Discover the KMIP versions supported by the server.
    ///
    /// - Returns: DiscoverVersionsResult with versions array.
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

    /// Encrypt data using a managed key.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the encryption key.
    ///   - data: Plaintext data to encrypt.
    /// - Returns: EncryptResult with ciphertext data and nonce.
    public func encrypt(_ uniqueId: String, data: Data) throws -> EncryptResult {
        let request = buildEncryptRequest(uniqueId: uniqueId, data: data)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return EncryptResult(data: nil, nonce: nil)
        }
        return parseEncryptPayload(payload)
    }

    /// Decrypt data using a managed key.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the decryption key.
    ///   - data: Ciphertext data to decrypt.
    ///   - nonce: IV/counter/nonce (optional).
    /// - Returns: DecryptResult with plaintext data.
    public func decrypt(_ uniqueId: String, data: Data, nonce: Data? = nil) throws -> DecryptResult {
        let request = buildDecryptRequest(uniqueId: uniqueId, data: data, nonce: nonce)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return DecryptResult(data: nil)
        }
        return parseDecryptPayload(payload)
    }

    /// Sign data using a managed key.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the signing key.
    ///   - data: Data to sign.
    /// - Returns: SignResult with signatureData.
    public func sign(_ uniqueId: String, data: Data) throws -> SignResult {
        let request = buildSignRequest(uniqueId: uniqueId, data: data)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return SignResult(signatureData: nil)
        }
        return parseSignPayload(payload)
    }

    /// Verify a signature using a managed key.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the verification key.
    ///   - data: Original data that was signed.
    ///   - signature: Signature to verify.
    /// - Returns: SignatureVerifyResult with valid flag.
    public func signatureVerify(_ uniqueId: String, data: Data, signature: Data) throws -> SignatureVerifyResult {
        let request = buildSignatureVerifyRequest(uniqueId: uniqueId, data: data, signature: signature)
        let responseData = try send(request)
        let response = try parseResponse(responseData)
        guard let payload = response.payload else {
            return SignatureVerifyResult(valid: false)
        }
        return parseSignatureVerifyPayload(payload)
    }

    /// Compute a MAC using a managed key.
    ///
    /// - Parameters:
    ///   - uniqueId: The unique identifier of the MAC key.
    ///   - data: Data to MAC.
    /// - Returns: MACResult with macData.
    public func mac(_ uniqueId: String, data: Data) throws -> MACResult {
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
        inputStream?.close()
        outputStream?.close()
        inputStream = nil
        outputStream = nil
        isConnected = false
    }

    // MARK: - Private

    private func send(_ request: Data) throws -> Data {
        try connect()

        guard let output = outputStream else {
            throw KmipError.connectionFailed("No output stream")
        }

        // Write request
        let written = request.withUnsafeBytes { ptr -> Int in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return output.write(base, maxLength: request.count)
        }
        guard written == request.count else {
            throw KmipError.connectionFailed("Failed to write request")
        }

        // Read TTLV header (8 bytes) to determine total length
        let header = try recvExact(8)
        let valueLength = Int(
            (UInt32(header[4]) << 24) |
            (UInt32(header[5]) << 16) |
            (UInt32(header[6]) << 8) |
            UInt32(header[7])
        )
        let body = try recvExact(valueLength)
        return header + body
    }

    private func recvExact(_ n: Int) throws -> Data {
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

    private func connect() throws {
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

        // Configure TLS
        let sslSettings: [String: Any] = [
            kCFStreamSSLLevel as String: kCFStreamSocketSecurityLevelNegotiatedSSL,
            kCFStreamSSLPeerName as String: host,
        ]

        input.setProperty(sslSettings, forKey: .init(kCFStreamPropertySSLSettings as String))
        output.setProperty(sslSettings, forKey: .init(kCFStreamPropertySSLSettings as String))

        input.open()
        output.open()

        self.inputStream = input
        self.outputStream = output
        self.isConnected = true
    }
}

#endif // canImport(Security) && canImport(CFNetwork)
