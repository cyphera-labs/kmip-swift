//
// OperationsTests.swift
// CypheraKmipTests
//
// Tests for KMIP request building and response parsing.
//

import XCTest
@testable import CypheraKmip

final class OperationsTests: XCTestCase {

    // MARK: - Request building — Locate

    func testBuildLocateRequestProducesValidTTLV() throws {
        let request = buildLocateRequest(name: "test-key")
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
        XCTAssertEqual(decoded.type, TtlvType.structure.rawValue)
    }

    func testBuildLocateRequestContainsProtocolVersion14() throws {
        let decoded = try decodeTTLV(buildLocateRequest(name: "k"))
        let header = findChild(decoded, tag: Tag.RequestHeader)
        XCTAssertNotNil(header)
        let version = findChild(header!, tag: Tag.ProtocolVersion)
        XCTAssertNotNil(version)
        let major = findChild(version!, tag: Tag.ProtocolVersionMajor)
        let minor = findChild(version!, tag: Tag.ProtocolVersionMinor)
        XCTAssertNotNil(major)
        XCTAssertNotNil(minor)
        if case .integer(let v) = major!.value { XCTAssertEqual(v, PROTOCOL_MAJOR) }
        if case .integer(let v) = minor!.value { XCTAssertEqual(v, PROTOCOL_MINOR) }
    }

    func testBuildLocateRequestHasBatchCount1() throws {
        let decoded = try decodeTTLV(buildLocateRequest(name: "k"))
        let header = findChild(decoded, tag: Tag.RequestHeader)!
        let count = findChild(header, tag: Tag.BatchCount)
        XCTAssertNotNil(count)
        if case .integer(let v) = count!.value { XCTAssertEqual(v, 1) }
    }

    func testBuildLocateRequestHasLocateOperation() throws {
        let decoded = try decodeTTLV(buildLocateRequest(name: "k"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let op = findChild(batch, tag: Tag.Operation)
        XCTAssertNotNil(op)
        if case .enumeration(let v) = op!.value {
            XCTAssertEqual(v, KmipOperation.Locate)
        } else {
            XCTFail("Expected enumeration value")
        }
    }

    func testBuildLocateRequestContainsNameAttribute() throws {
        let decoded = try decodeTTLV(buildLocateRequest(name: "my-key"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let attr = findChild(payload, tag: Tag.Attribute)!
        let attrName = findChild(attr, tag: Tag.AttributeName)!
        if case .textString(let v) = attrName.value { XCTAssertEqual(v, "Name") }
        let attrValue = findChild(attr, tag: Tag.AttributeValue)!
        let nameValue = findChild(attrValue, tag: Tag.NameValue)!
        if case .textString(let v) = nameValue.value { XCTAssertEqual(v, "my-key") }
    }

    // MARK: - Request building — Get

    func testBuildGetRequestProducesValidTTLV() throws {
        let request = buildGetRequest(uniqueId: "unique-id-123")
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
    }

    func testBuildGetRequestHasGetOperation() throws {
        let decoded = try decodeTTLV(buildGetRequest(uniqueId: "uid"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let op = findChild(batch, tag: Tag.Operation)!
        if case .enumeration(let v) = op.value {
            XCTAssertEqual(v, KmipOperation.Get)
        } else {
            XCTFail("Expected enumeration value")
        }
    }

    func testBuildGetRequestContainsUniqueIdentifier() throws {
        let decoded = try decodeTTLV(buildGetRequest(uniqueId: "uid-456"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let uid = findChild(payload, tag: Tag.UniqueIdentifier)!
        if case .textString(let v) = uid.value {
            XCTAssertEqual(v, "uid-456")
        } else {
            XCTFail("Expected text string value")
        }
    }

    // MARK: - Request building — Create

    func testBuildCreateRequestProducesValidTTLV() throws {
        let request = buildCreateRequest(name: "new-key")
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
    }

    func testBuildCreateRequestHasCreateOperation() throws {
        let decoded = try decodeTTLV(buildCreateRequest(name: "k"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let op = findChild(batch, tag: Tag.Operation)!
        if case .enumeration(let v) = op.value {
            XCTAssertEqual(v, KmipOperation.Create)
        } else {
            XCTFail("Expected enumeration value")
        }
    }

    func testBuildCreateRequestUsesSymmetricKeyObjectType() throws {
        let decoded = try decodeTTLV(buildCreateRequest(name: "k"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let objType = findChild(payload, tag: Tag.ObjectType)!
        if case .enumeration(let v) = objType.value {
            XCTAssertEqual(v, KmipObjectType.SymmetricKey)
        } else {
            XCTFail("Expected enumeration value")
        }
    }

    func testBuildCreateRequestDefaultsToAES() throws {
        let decoded = try decodeTTLV(buildCreateRequest(name: "k"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let tmpl = findChild(payload, tag: Tag.TemplateAttribute)!
        let attrs = findChildren(tmpl, tag: Tag.Attribute)
        let algoAttr = attrs.first { attr in
            if let name = findChild(attr, tag: Tag.AttributeName),
               case .textString(let v) = name.value { return v == "Cryptographic Algorithm" }
            return false
        }
        XCTAssertNotNil(algoAttr)
        let algoValue = findChild(algoAttr!, tag: Tag.AttributeValue)!
        if case .enumeration(let v) = algoValue.value {
            XCTAssertEqual(v, KmipAlgorithm.AES)
        } else {
            XCTFail("Expected enumeration value")
        }
    }

    func testBuildCreateRequestDefaultsTo256BitLength() throws {
        let decoded = try decodeTTLV(buildCreateRequest(name: "k"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let tmpl = findChild(payload, tag: Tag.TemplateAttribute)!
        let attrs = findChildren(tmpl, tag: Tag.Attribute)
        let lenAttr = attrs.first { attr in
            if let name = findChild(attr, tag: Tag.AttributeName),
               case .textString(let v) = name.value { return v == "Cryptographic Length" }
            return false
        }
        XCTAssertNotNil(lenAttr)
        let lenValue = findChild(lenAttr!, tag: Tag.AttributeValue)!
        if case .integer(let v) = lenValue.value {
            XCTAssertEqual(v, 256)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testBuildCreateRequestIncludesEncryptDecryptUsageMask() throws {
        let decoded = try decodeTTLV(buildCreateRequest(name: "k"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let tmpl = findChild(payload, tag: Tag.TemplateAttribute)!
        let attrs = findChildren(tmpl, tag: Tag.Attribute)
        let usageAttr = attrs.first { attr in
            if let name = findChild(attr, tag: Tag.AttributeName),
               case .textString(let v) = name.value { return v == "Cryptographic Usage Mask" }
            return false
        }
        XCTAssertNotNil(usageAttr)
        let usageValue = findChild(usageAttr!, tag: Tag.AttributeValue)!
        if case .integer(let v) = usageValue.value {
            XCTAssertEqual(v, Int32(KmipUsageMask.Encrypt | KmipUsageMask.Decrypt))
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testBuildCreateRequestIncludesKeyName() throws {
        let decoded = try decodeTTLV(buildCreateRequest(name: "prod-key"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let tmpl = findChild(payload, tag: Tag.TemplateAttribute)!
        let attrs = findChildren(tmpl, tag: Tag.Attribute)
        let nameAttr = attrs.first { attr in
            if let name = findChild(attr, tag: Tag.AttributeName),
               case .textString(let v) = name.value { return v == "Name" }
            return false
        }
        XCTAssertNotNil(nameAttr)
        let nameStruct = findChild(nameAttr!, tag: Tag.AttributeValue)!
        let nameValue = findChild(nameStruct, tag: Tag.NameValue)!
        if case .textString(let v) = nameValue.value {
            XCTAssertEqual(v, "prod-key")
        } else {
            XCTFail("Expected text string value")
        }
    }

    func testBuildCreateRequestAcceptsCustomAlgorithmAndLength() throws {
        let decoded = try decodeTTLV(buildCreateRequest(name: "k", algorithm: KmipAlgorithm.TripleDES, length: 192))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let tmpl = findChild(payload, tag: Tag.TemplateAttribute)!
        let attrs = findChildren(tmpl, tag: Tag.Attribute)

        let algoAttr = attrs.first { attr in
            if let name = findChild(attr, tag: Tag.AttributeName),
               case .textString(let v) = name.value { return v == "Cryptographic Algorithm" }
            return false
        }!
        let algoValue = findChild(algoAttr, tag: Tag.AttributeValue)!
        if case .enumeration(let v) = algoValue.value {
            XCTAssertEqual(v, KmipAlgorithm.TripleDES)
        }

        let lenAttr = attrs.first { attr in
            if let name = findChild(attr, tag: Tag.AttributeName),
               case .textString(let v) = name.value { return v == "Cryptographic Length" }
            return false
        }!
        let lenValue = findChild(lenAttr, tag: Tag.AttributeValue)!
        if case .integer(let v) = lenValue.value {
            XCTAssertEqual(v, 192)
        }
    }

    // MARK: - Response parsing

    private func buildMockResponse(operation: UInt32, status: UInt32, payloadChildren: [Data] = []) -> Data {
        var batchChildren = [
            encodeEnum(tag: Tag.Operation, value: operation),
            encodeEnum(tag: Tag.ResultStatus, value: status),
        ]
        if !payloadChildren.isEmpty {
            batchChildren.append(encodeStructure(tag: Tag.ResponsePayload, children: payloadChildren))
        }
        return encodeStructure(tag: Tag.ResponseMessage, children: [
            encodeStructure(tag: Tag.ResponseHeader, children: [
                encodeStructure(tag: Tag.ProtocolVersion, children: [
                    encodeInteger(tag: Tag.ProtocolVersionMajor, value: 1),
                    encodeInteger(tag: Tag.ProtocolVersionMinor, value: 4),
                ]),
                encodeInteger(tag: Tag.BatchCount, value: 1),
            ]),
            encodeStructure(tag: Tag.BatchItem, children: batchChildren),
        ])
    }

    func testParseResponseExtractsOperationAndStatus() throws {
        let response = buildMockResponse(
            operation: KmipOperation.Locate,
            status: KmipResultStatus.Success,
            payloadChildren: [encodeTextString(tag: Tag.UniqueIdentifier, value: "id-1")]
        )
        let result = try parseResponse(response)
        XCTAssertEqual(result.operation, KmipOperation.Locate)
        XCTAssertEqual(result.resultStatus, KmipResultStatus.Success)
    }

    func testParseResponseThrowsOnOperationFailure() {
        var batchChildren = [
            encodeEnum(tag: Tag.Operation, value: KmipOperation.Get),
            encodeEnum(tag: Tag.ResultStatus, value: KmipResultStatus.OperationFailed),
            encodeTextString(tag: Tag.ResultMessage, value: "Item Not Found"),
        ]
        let response = encodeStructure(tag: Tag.ResponseMessage, children: [
            encodeStructure(tag: Tag.ResponseHeader, children: [
                encodeStructure(tag: Tag.ProtocolVersion, children: [
                    encodeInteger(tag: Tag.ProtocolVersionMajor, value: 1),
                    encodeInteger(tag: Tag.ProtocolVersionMinor, value: 4),
                ]),
                encodeInteger(tag: Tag.BatchCount, value: 1),
            ]),
            encodeStructure(tag: Tag.BatchItem, children: batchChildren),
        ])
        XCTAssertThrowsError(try parseResponse(response)) { error in
            if case KmipError.operationFailed(let message, _, _) = error {
                XCTAssertTrue(message.contains("Item Not Found"))
            } else {
                XCTFail("Expected KmipError.operationFailed, got \(error)")
            }
        }
    }

    func testParseResponseThrowsOnNonResponseMessageTag() {
        let badMsg = encodeStructure(tag: Tag.RequestMessage, children: [
            encodeStructure(tag: Tag.RequestHeader, children: []),
            encodeStructure(tag: Tag.BatchItem, children: []),
        ])
        XCTAssertThrowsError(try parseResponse(badMsg)) { error in
            if case KmipError.unexpectedTag(_, _) = error {
                // expected
            } else {
                XCTFail("Expected KmipError.unexpectedTag, got \(error)")
            }
        }
    }

    func testParseLocatePayloadExtractsUniqueIdentifiers() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.UniqueIdentifier, value: "uid-1"),
            encodeTextString(tag: Tag.UniqueIdentifier, value: "uid-2"),
            encodeTextString(tag: Tag.UniqueIdentifier, value: "uid-3"),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseLocatePayload(payload)
        XCTAssertEqual(result.uniqueIdentifiers, ["uid-1", "uid-2", "uid-3"])
    }

    func testParseLocatePayloadHandlesEmptyResult() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [])
        let payload = try decodeTTLV(payloadData)
        let result = parseLocatePayload(payload)
        XCTAssertEqual(result.uniqueIdentifiers, [])
    }

    func testParseLocatePayloadHandlesSingleResult() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.UniqueIdentifier, value: "only-one"),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseLocatePayload(payload)
        XCTAssertEqual(result.uniqueIdentifiers, ["only-one"])
    }

    func testParseGetPayloadExtractsKeyMaterial() throws {
        let keyBytes = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ])
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.UniqueIdentifier, value: "uid-99"),
            encodeEnum(tag: Tag.ObjectType, value: KmipObjectType.SymmetricKey),
            encodeStructure(tag: Tag.SymmetricKey, children: [
                encodeStructure(tag: Tag.KeyBlock, children: [
                    encodeEnum(tag: Tag.KeyFormatType, value: KmipKeyFormatType.Raw),
                    encodeStructure(tag: Tag.KeyValue, children: [
                        encodeByteString(tag: Tag.KeyMaterial, value: keyBytes),
                    ]),
                ]),
            ]),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseGetPayload(payload)
        XCTAssertEqual(result.uniqueIdentifier, "uid-99")
        XCTAssertEqual(result.objectType, KmipObjectType.SymmetricKey)
        XCTAssertEqual(result.keyMaterial, keyBytes)
    }

    func testParseGetPayloadReturnsNilKeyMaterialWhenNoSymmetricKey() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.UniqueIdentifier, value: "uid-50"),
            encodeEnum(tag: Tag.ObjectType, value: KmipObjectType.Certificate),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseGetPayload(payload)
        XCTAssertEqual(result.uniqueIdentifier, "uid-50")
        XCTAssertNil(result.keyMaterial)
    }

    func testParseCreatePayloadExtractsObjectTypeAndUniqueID() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeEnum(tag: Tag.ObjectType, value: KmipObjectType.SymmetricKey),
            encodeTextString(tag: Tag.UniqueIdentifier, value: "new-uid-7"),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseCreatePayload(payload)
        XCTAssertEqual(result.objectType, KmipObjectType.SymmetricKey)
        XCTAssertEqual(result.uniqueIdentifier, "new-uid-7")
    }

    // MARK: - Round-trip verification

    func testLocateRequestRoundTrips() throws {
        let request = buildLocateRequest(name: "round-trip-key")
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
        let reEncoded = buildLocateRequest(name: "round-trip-key")
        XCTAssertEqual(request, reEncoded)
    }

    func testGetRequestRoundTrips() throws {
        let request = buildGetRequest(uniqueId: "uid-abc")
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let uid = findChild(payload, tag: Tag.UniqueIdentifier)!
        if case .textString(let v) = uid.value {
            XCTAssertEqual(v, "uid-abc")
        } else {
            XCTFail("Expected text string value")
        }
    }

    func testCreateRequestRoundTrips() throws {
        let request = buildCreateRequest(name: "rt-key", algorithm: KmipAlgorithm.AES, length: 128)
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let op = findChild(batch, tag: Tag.Operation)!
        if case .enumeration(let v) = op.value {
            XCTAssertEqual(v, KmipOperation.Create)
        } else {
            XCTFail("Expected enumeration value")
        }
    }
}
