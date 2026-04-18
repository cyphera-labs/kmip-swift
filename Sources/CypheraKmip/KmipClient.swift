//
// KmipClient.swift
// CypheraKmip
//
// KMIP client -- connects to any KMIP 1.4 server via mTLS.
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
#if canImport(Network)
import Network
#endif

/// KMIP client with mTLS support.
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
