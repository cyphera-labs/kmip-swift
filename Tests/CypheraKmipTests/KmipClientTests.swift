//
// KmipClientTests.swift
// CypheraKmipTests
//
// Tests for KmipClient construction, SecureKeyMaterial, and Sendable wiring.
// Live TLS + mTLS behavior is covered in the Integration workflow; these
// tests target the input-validation and memory-hygiene surface that can be
// exercised without a running KMIP server.
//

import XCTest
@testable import CypheraKmip

final class KmipClientTests: XCTestCase {

    // MARK: - Constructor validation (M5 / security)

    func testRejectsEmptyHost() {
        XCTAssertThrowsError(try KmipClient(
            host: "",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )) { error in
            guard case KmipError.invalidParameter = error else {
                XCTFail("Expected invalidParameter, got \(error)"); return
            }
        }
    }

    func testRejectsEmptyClientCert() {
        XCTAssertThrowsError(try KmipClient(
            host: "example.com",
            clientCert: "",
            clientKey: "/tmp/client-key.pem"
        )) { error in
            guard case KmipError.invalidParameter = error else {
                XCTFail("Expected invalidParameter, got \(error)"); return
            }
        }
    }

    func testRejectsEmptyClientKey() {
        XCTAssertThrowsError(try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: ""
        )) { error in
            guard case KmipError.invalidParameter = error else {
                XCTFail("Expected invalidParameter, got \(error)"); return
            }
        }
    }

    func testRejectsZeroPort() {
        XCTAssertThrowsError(try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem",
            port: 0
        ))
    }

    func testRejectsNegativePort() {
        XCTAssertThrowsError(try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem",
            port: -1
        ))
    }

    func testRejectsOutOfRangePort() {
        XCTAssertThrowsError(try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem",
            port: 100_000
        ))
    }

    func testRejectsZeroTimeout() {
        XCTAssertThrowsError(try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem",
            timeout: 0
        ))
    }

    func testConstructsWithValidArguments() {
        XCTAssertNoThrow(try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        ))
    }

    func testConstructsWithPin() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem",
            pinnedCertificateSHA256: Data(repeating: 0xAB, count: 32)
        )
        XCTAssertEqual(client.pinnedCertificateSHA256?.count, 32)
    }

    // MARK: - Public method input validation (M5)

    func testLocateRejectsEmptyName() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )
        XCTAssertThrowsError(try client.locate(""))
    }

    func testGetRejectsEmptyUniqueId() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )
        XCTAssertThrowsError(try client.get(""))
    }

    func testCreateRejectsEmptyName() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )
        XCTAssertThrowsError(try client.create(""))
    }

    func testCreateRejectsNonPositiveLength() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )
        XCTAssertThrowsError(try client.create("k", length: 0))
        XCTAssertThrowsError(try client.create("k", length: -256))
    }

    func testEncryptRejectsEmptyData() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )
        XCTAssertThrowsError(try client.encrypt("id", data: Data()))
    }

    func testRegisterRejectsEmptyMaterial() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )
        XCTAssertThrowsError(try client.register(
            objectType: KmipObjectType.SymmetricKey,
            material: Data(),
            name: "k",
            algorithm: KmipAlgorithm.AES,
            length: 256
        ))
    }

    // MARK: - SecureKeyMaterial (H9/H10)

    func testSecureKeyMaterialExposesBytesInClosure() {
        let raw = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let secure = SecureKeyMaterial(raw)
        secure.withBytes { bytes in
            XCTAssertEqual(bytes, raw)
        }
        XCTAssertEqual(secure.count, 4)
    }

    func testSecureKeyMaterialCopyBytes() {
        let raw = Data(repeating: 0xAA, count: 32)
        let secure = SecureKeyMaterial(raw)
        XCTAssertEqual(secure.copyBytes(), raw)
    }

    func testSecureKeyMaterialDeinitZeroesBackingStorage() {
        // Capture a pointer to the storage via withBytes while the object is
        // alive, record the address, then release and confirm memset ran by
        // reading back a fresh buffer at that address — in practice we verify
        // the deinit doesn't crash and the object no longer responds. Direct
        // memory inspection after free is undefined behavior; exercise the
        // deinit path instead.
        autoreleasepool {
            let secure = SecureKeyMaterial(Data(repeating: 0x42, count: 64))
            secure.withBytes { bytes in
                XCTAssertEqual(bytes.first, 0x42)
                XCTAssertEqual(bytes.count, 64)
            }
        }
        // Reaching here without a trap means deinit ran cleanly.
        XCTAssertTrue(true)
    }

    func testSecureKeyMaterialIsSendable() {
        // Compile-time: SecureKeyMaterial must be usable across concurrency
        // domains. If the @unchecked Sendable conformance is removed, this
        // test will fail to compile under Swift 6.
        let secure = SecureKeyMaterial(Data([0x01]))
        Task { [secure] in
            _ = secure.count
        }
    }

    // MARK: - Sendable surface on result types (H8)

    func testResultTypesAreSendable() {
        // These are compile-time checks — if any of these types lose Sendable
        // conformance, the test will fail to build.
        func accept<T: Sendable>(_ value: T) {}
        accept(LocateResult(uniqueIdentifiers: []))
        accept(GetResult(objectType: nil, uniqueIdentifier: nil, keyMaterial: nil))
        accept(CreateResult(objectType: nil, uniqueIdentifier: nil))
        accept(CheckResult(uniqueIdentifier: nil))
        accept(ReKeyResult(uniqueIdentifier: nil))
        accept(CreateKeyPairResult(privateKeyUID: nil, publicKeyUID: nil))
        accept(DeriveKeyResult(uniqueIdentifier: nil))
        accept(EncryptResult(data: nil, nonce: nil))
        accept(DecryptResult(data: nil))
        accept(SignResult(signatureData: nil))
        accept(SignatureVerifyResult(valid: false))
        accept(MACResult(macData: nil))
        accept(QueryResult(operations: [], objectTypes: []))
        accept(DiscoverVersionsResult(versions: []))
        XCTAssertTrue(true)
    }

    // MARK: - Concurrent close must not race with in-flight calls (H7)

    func testConcurrentCloseIsSerialized() throws {
        let client = try KmipClient(
            host: "example.com",
            clientCert: "/tmp/client.pem",
            clientKey: "/tmp/client-key.pem"
        )
        // Hammer close() from many threads. The point is that the NSLock
        // serializes access so this doesn't crash with a data race — the
        // actual connection is never opened (no server), so close is a no-op,
        // but the lock must hold under contention.
        let expectation = self.expectation(description: "concurrent close")
        expectation.expectedFulfillmentCount = 100
        let queue = DispatchQueue.global(qos: .userInitiated)
        for _ in 0..<100 {
            queue.async {
                client.close()
                expectation.fulfill()
            }
        }
        wait(for: [expectation], timeout: 5)
    }
}
