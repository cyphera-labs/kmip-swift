//
// OperationsTests.swift
// CypheraKmipTests
//
// Tests for all 27 KMIP request builders and response parsers.
//

import XCTest
@testable import CypheraKmip

final class OperationsTests: XCTestCase {

    // MARK: - Helper

    private func buildMockResponse(operation: UInt32, status: UInt32, payloadChildren: [Data] = []) -> Data {
        var batchChildren: [Data] = [
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

    /// Verify a request has the expected operation enum in the BatchItem.
    private func assertOperation(_ request: Data, expected: UInt32, file: StaticString = #filePath, line: UInt = #line) throws {
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage, file: file, line: line)
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let op = findChild(batch, tag: Tag.Operation)!
        if case .enumeration(let v) = op.value {
            XCTAssertEqual(v, expected, file: file, line: line)
        } else {
            XCTFail("Expected enumeration value", file: file, line: line)
        }
    }

    /// Verify a request has a UID in the payload.
    private func assertPayloadUID(_ request: Data, expected: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let decoded = try decodeTTLV(request)
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let uid = findChild(payload, tag: Tag.UniqueIdentifier)!
        if case .textString(let v) = uid.value {
            XCTAssertEqual(v, expected, file: file, line: line)
        } else {
            XCTFail("Expected text string value", file: file, line: line)
        }
    }

    // MARK: - Request building -- Locate

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
        try assertOperation(buildLocateRequest(name: "k"), expected: KmipOperation.Locate)
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

    // MARK: - Request building -- Get

    func testBuildGetRequestProducesValidTTLV() throws {
        let request = buildGetRequest(uniqueId: "unique-id-123")
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
    }

    func testBuildGetRequestHasGetOperation() throws {
        try assertOperation(buildGetRequest(uniqueId: "uid"), expected: KmipOperation.Get)
    }

    func testBuildGetRequestContainsUniqueIdentifier() throws {
        try assertPayloadUID(buildGetRequest(uniqueId: "uid-456"), expected: "uid-456")
    }

    // MARK: - Request building -- Create

    func testBuildCreateRequestProducesValidTTLV() throws {
        let request = buildCreateRequest(name: "new-key")
        let decoded = try decodeTTLV(request)
        XCTAssertEqual(decoded.tag, Tag.RequestMessage)
    }

    func testBuildCreateRequestHasCreateOperation() throws {
        try assertOperation(buildCreateRequest(name: "k"), expected: KmipOperation.Create)
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

    // MARK: - Request building -- Activate / Destroy / Check

    func testBuildActivateRequestHasCorrectOperation() throws {
        try assertOperation(buildActivateRequest(uniqueId: "uid-1"), expected: KmipOperation.Activate)
        try assertPayloadUID(buildActivateRequest(uniqueId: "uid-1"), expected: "uid-1")
    }

    func testBuildDestroyRequestHasCorrectOperation() throws {
        try assertOperation(buildDestroyRequest(uniqueId: "uid-2"), expected: KmipOperation.Destroy)
        try assertPayloadUID(buildDestroyRequest(uniqueId: "uid-2"), expected: "uid-2")
    }

    func testBuildCheckRequestHasCorrectOperation() throws {
        try assertOperation(buildCheckRequest(uniqueId: "uid-3"), expected: KmipOperation.Check)
        try assertPayloadUID(buildCheckRequest(uniqueId: "uid-3"), expected: "uid-3")
    }

    // MARK: - Request building -- CreateKeyPair

    func testBuildCreateKeyPairRequestHasCorrectOperation() throws {
        let request = buildCreateKeyPairRequest(name: "kp", algorithm: KmipAlgorithm.RSA, length: 2048)
        try assertOperation(request, expected: KmipOperation.CreateKeyPair)
    }

    func testBuildCreateKeyPairRequestContainsSignVerifyUsageMask() throws {
        let decoded = try decodeTTLV(buildCreateKeyPairRequest(name: "kp", algorithm: KmipAlgorithm.RSA, length: 2048))
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
            XCTAssertEqual(v, Int32(KmipUsageMask.Sign | KmipUsageMask.Verify))
        } else {
            XCTFail("Expected integer value")
        }
    }

    // MARK: - Request building -- Register

    func testBuildRegisterRequestHasCorrectOperation() throws {
        let material = Data([0x01, 0x02, 0x03, 0x04])
        let request = buildRegisterRequest(objectType: KmipObjectType.SymmetricKey, material: material, name: "reg-key", algorithm: KmipAlgorithm.AES, length: 32)
        try assertOperation(request, expected: KmipOperation.Register)
    }

    func testBuildRegisterRequestContainsKeyMaterial() throws {
        let material = Data([0xAA, 0xBB, 0xCC])
        let decoded = try decodeTTLV(buildRegisterRequest(objectType: KmipObjectType.SymmetricKey, material: material, name: "reg-key", algorithm: KmipAlgorithm.AES, length: 24))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let symKey = findChild(payload, tag: Tag.SymmetricKey)!
        let keyBlock = findChild(symKey, tag: Tag.KeyBlock)!
        let keyValue = findChild(keyBlock, tag: Tag.KeyValue)!
        let keyMat = findChild(keyValue, tag: Tag.KeyMaterial)!
        if case .byteString(let v) = keyMat.value {
            XCTAssertEqual(v, material)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    func testBuildRegisterRequestWithEmptyNameOmitsTemplate() throws {
        let material = Data([0x01])
        let decoded = try decodeTTLV(buildRegisterRequest(objectType: KmipObjectType.SymmetricKey, material: material, name: "", algorithm: KmipAlgorithm.AES, length: 8))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let tmpl = findChild(payload, tag: Tag.TemplateAttribute)
        XCTAssertNil(tmpl)
    }

    // MARK: - Request building -- ReKey

    func testBuildReKeyRequestHasCorrectOperation() throws {
        try assertOperation(buildReKeyRequest(uniqueId: "rk-1"), expected: KmipOperation.ReKey)
        try assertPayloadUID(buildReKeyRequest(uniqueId: "rk-1"), expected: "rk-1")
    }

    // MARK: - Request building -- DeriveKey

    func testBuildDeriveKeyRequestHasCorrectOperation() throws {
        let request = buildDeriveKeyRequest(uniqueId: "dk-1", derivationData: Data([0x01]), name: "derived", length: 256)
        try assertOperation(request, expected: KmipOperation.DeriveKey)
        try assertPayloadUID(request, expected: "dk-1")
    }

    func testBuildDeriveKeyRequestContainsDerivationData() throws {
        let derivData = Data([0xDE, 0xAD])
        let decoded = try decodeTTLV(buildDeriveKeyRequest(uniqueId: "dk-2", derivationData: derivData, name: "derived", length: 128))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let params = findChild(payload, tag: Tag.DerivationParameters)!
        let data = findChild(params, tag: Tag.DerivationData)!
        if case .byteString(let v) = data.value {
            XCTAssertEqual(v, derivData)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    // MARK: - Request building -- GetAttributes / GetAttributeList

    func testBuildGetAttributesRequestHasCorrectOperation() throws {
        try assertOperation(buildGetAttributesRequest(uniqueId: "ga-1"), expected: KmipOperation.GetAttributes)
    }

    func testBuildGetAttributeListRequestHasCorrectOperation() throws {
        try assertOperation(buildGetAttributeListRequest(uniqueId: "gal-1"), expected: KmipOperation.GetAttributeList)
    }

    // MARK: - Request building -- AddAttribute / ModifyAttribute / DeleteAttribute

    func testBuildAddAttributeRequestHasCorrectOperation() throws {
        let request = buildAddAttributeRequest(uniqueId: "aa-1", attrName: "x-custom", attrValue: "val")
        try assertOperation(request, expected: KmipOperation.AddAttribute)
        try assertPayloadUID(request, expected: "aa-1")
    }

    func testBuildAddAttributeRequestContainsAttribute() throws {
        let decoded = try decodeTTLV(buildAddAttributeRequest(uniqueId: "aa-2", attrName: "x-tag", attrValue: "hello"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let attr = findChild(payload, tag: Tag.Attribute)!
        let attrName = findChild(attr, tag: Tag.AttributeName)!
        if case .textString(let v) = attrName.value { XCTAssertEqual(v, "x-tag") }
        let attrValue = findChild(attr, tag: Tag.AttributeValue)!
        if case .textString(let v) = attrValue.value { XCTAssertEqual(v, "hello") }
    }

    func testBuildModifyAttributeRequestHasCorrectOperation() throws {
        let request = buildModifyAttributeRequest(uniqueId: "ma-1", attrName: "x-custom", attrValue: "new")
        try assertOperation(request, expected: KmipOperation.ModifyAttribute)
    }

    func testBuildDeleteAttributeRequestHasCorrectOperation() throws {
        let request = buildDeleteAttributeRequest(uniqueId: "da-1", attrName: "x-custom")
        try assertOperation(request, expected: KmipOperation.DeleteAttribute)
    }

    func testBuildDeleteAttributeRequestContainsAttributeName() throws {
        let decoded = try decodeTTLV(buildDeleteAttributeRequest(uniqueId: "da-2", attrName: "x-tag"))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let attr = findChild(payload, tag: Tag.Attribute)!
        let attrName = findChild(attr, tag: Tag.AttributeName)!
        if case .textString(let v) = attrName.value { XCTAssertEqual(v, "x-tag") }
        // No attribute value in delete
        XCTAssertNil(findChild(attr, tag: Tag.AttributeValue))
    }

    // MARK: - Request building -- ObtainLease

    func testBuildObtainLeaseRequestHasCorrectOperation() throws {
        try assertOperation(buildObtainLeaseRequest(uniqueId: "ol-1"), expected: KmipOperation.ObtainLease)
    }

    // MARK: - Request building -- Revoke

    func testBuildRevokeRequestHasCorrectOperation() throws {
        let request = buildRevokeRequest(uniqueId: "rv-1", reason: 1)
        try assertOperation(request, expected: KmipOperation.Revoke)
        try assertPayloadUID(request, expected: "rv-1")
    }

    func testBuildRevokeRequestContainsRevocationReason() throws {
        let decoded = try decodeTTLV(buildRevokeRequest(uniqueId: "rv-2", reason: 5))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let reason = findChild(payload, tag: Tag.RevocationReason)!
        let code = findChild(reason, tag: Tag.RevocationReasonCode)!
        if case .enumeration(let v) = code.value {
            XCTAssertEqual(v, 5)
        } else {
            XCTFail("Expected enumeration value")
        }
    }

    // MARK: - Request building -- Archive / Recover

    func testBuildArchiveRequestHasCorrectOperation() throws {
        try assertOperation(buildArchiveRequest(uniqueId: "ar-1"), expected: KmipOperation.Archive)
    }

    func testBuildRecoverRequestHasCorrectOperation() throws {
        try assertOperation(buildRecoverRequest(uniqueId: "rc-1"), expected: KmipOperation.Recover)
    }

    // MARK: - Request building -- Query / Poll / DiscoverVersions

    func testBuildQueryRequestHasCorrectOperation() throws {
        try assertOperation(buildQueryRequest(), expected: KmipOperation.Query)
    }

    func testBuildPollRequestHasCorrectOperation() throws {
        try assertOperation(buildPollRequest(), expected: KmipOperation.Poll)
    }

    func testBuildDiscoverVersionsRequestHasCorrectOperation() throws {
        try assertOperation(buildDiscoverVersionsRequest(), expected: KmipOperation.DiscoverVersions)
    }

    func testEmptyPayloadRequestsHaveEmptyPayload() throws {
        for (op, builder) in [
            (KmipOperation.Query, buildQueryRequest()),
            (KmipOperation.Poll, buildPollRequest()),
            (KmipOperation.DiscoverVersions, buildDiscoverVersionsRequest()),
        ] {
            let decoded = try decodeTTLV(builder)
            let batch = findChild(decoded, tag: Tag.BatchItem)!
            let payload = findChild(batch, tag: Tag.RequestPayload)!
            if case .structure(let children) = payload.value {
                XCTAssertEqual(children.count, 0, "Expected empty payload for operation 0x\(String(op, radix: 16))")
            }
        }
    }

    // MARK: - Request building -- Encrypt

    func testBuildEncryptRequestHasCorrectOperation() throws {
        let request = buildEncryptRequest(uniqueId: "enc-1", data: Data([0x01]))
        try assertOperation(request, expected: KmipOperation.Encrypt)
        try assertPayloadUID(request, expected: "enc-1")
    }

    func testBuildEncryptRequestContainsData() throws {
        let plaintext = Data([0xCA, 0xFE, 0xBA, 0xBE])
        let decoded = try decodeTTLV(buildEncryptRequest(uniqueId: "enc-2", data: plaintext))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let dataItem = findChild(payload, tag: Tag.Data)!
        if case .byteString(let v) = dataItem.value {
            XCTAssertEqual(v, plaintext)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    // MARK: - Request building -- Decrypt

    func testBuildDecryptRequestHasCorrectOperation() throws {
        let request = buildDecryptRequest(uniqueId: "dec-1", data: Data([0x01]))
        try assertOperation(request, expected: KmipOperation.Decrypt)
    }

    func testBuildDecryptRequestWithNonce() throws {
        let nonce = Data([0xAA, 0xBB])
        let decoded = try decodeTTLV(buildDecryptRequest(uniqueId: "dec-2", data: Data([0x01]), nonce: nonce))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let nonceItem = findChild(payload, tag: Tag.IVCounterNonce)!
        if case .byteString(let v) = nonceItem.value {
            XCTAssertEqual(v, nonce)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    func testBuildDecryptRequestWithoutNonce() throws {
        let decoded = try decodeTTLV(buildDecryptRequest(uniqueId: "dec-3", data: Data([0x01])))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        XCTAssertNil(findChild(payload, tag: Tag.IVCounterNonce))
    }

    // MARK: - Request building -- Sign

    func testBuildSignRequestHasCorrectOperation() throws {
        let request = buildSignRequest(uniqueId: "sig-1", data: Data([0x01]))
        try assertOperation(request, expected: KmipOperation.Sign)
        try assertPayloadUID(request, expected: "sig-1")
    }

    // MARK: - Request building -- SignatureVerify

    func testBuildSignatureVerifyRequestHasCorrectOperation() throws {
        let request = buildSignatureVerifyRequest(uniqueId: "sv-1", data: Data([0x01]), signature: Data([0x02]))
        try assertOperation(request, expected: KmipOperation.SignatureVerify)
    }

    func testBuildSignatureVerifyRequestContainsSignatureData() throws {
        let sig = Data([0xDE, 0xAD])
        let decoded = try decodeTTLV(buildSignatureVerifyRequest(uniqueId: "sv-2", data: Data([0x01]), signature: sig))
        let batch = findChild(decoded, tag: Tag.BatchItem)!
        let payload = findChild(batch, tag: Tag.RequestPayload)!
        let sigItem = findChild(payload, tag: Tag.SignatureData)!
        if case .byteString(let v) = sigItem.value {
            XCTAssertEqual(v, sig)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    // MARK: - Request building -- MAC

    func testBuildMACRequestHasCorrectOperation() throws {
        let request = buildMACRequest(uniqueId: "mac-1", data: Data([0x01]))
        try assertOperation(request, expected: KmipOperation.MAC)
        try assertPayloadUID(request, expected: "mac-1")
    }

    // MARK: - Response parsing -- General

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
        let batchChildren: [Data] = [
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

    // MARK: - Response parsing -- Locate

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

    // MARK: - Response parsing -- Get

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

    // MARK: - Response parsing -- Create

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

    // MARK: - Response parsing -- Check

    func testParseCheckPayloadExtractsUID() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.UniqueIdentifier, value: "check-uid"),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseCheckPayload(payload)
        XCTAssertEqual(result.uniqueIdentifier, "check-uid")
    }

    // MARK: - Response parsing -- ReKey

    func testParseReKeyPayloadExtractsUID() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.UniqueIdentifier, value: "rekeyed-uid"),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseReKeyPayload(payload)
        XCTAssertEqual(result.uniqueIdentifier, "rekeyed-uid")
    }

    // MARK: - Response parsing -- CreateKeyPair

    func testParseCreateKeyPairPayloadExtractsUIDs() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.PrivateKeyUniqueIdentifier, value: "priv-uid"),
            encodeTextString(tag: Tag.PublicKeyUniqueIdentifier, value: "pub-uid"),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseCreateKeyPairPayload(payload)
        XCTAssertEqual(result.privateKeyUID, "priv-uid")
        XCTAssertEqual(result.publicKeyUID, "pub-uid")
    }

    // MARK: - Response parsing -- DeriveKey

    func testParseDeriveKeyPayloadExtractsUID() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeTextString(tag: Tag.UniqueIdentifier, value: "derived-uid"),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseDeriveKeyPayload(payload)
        XCTAssertEqual(result.uniqueIdentifier, "derived-uid")
    }

    // MARK: - Response parsing -- Encrypt

    func testParseEncryptPayloadExtractsDataAndNonce() throws {
        let ct = Data([0xDE, 0xAD])
        let nonce = Data([0xBE, 0xEF])
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeByteString(tag: Tag.Data, value: ct),
            encodeByteString(tag: Tag.IVCounterNonce, value: nonce),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseEncryptPayload(payload)
        XCTAssertEqual(result.data, ct)
        XCTAssertEqual(result.nonce, nonce)
    }

    func testParseEncryptPayloadHandlesMissingNonce() throws {
        let ct = Data([0x01])
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeByteString(tag: Tag.Data, value: ct),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseEncryptPayload(payload)
        XCTAssertEqual(result.data, ct)
        XCTAssertNil(result.nonce)
    }

    // MARK: - Response parsing -- Decrypt

    func testParseDecryptPayloadExtractsData() throws {
        let pt = Data([0xCA, 0xFE])
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeByteString(tag: Tag.Data, value: pt),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseDecryptPayload(payload)
        XCTAssertEqual(result.data, pt)
    }

    // MARK: - Response parsing -- Sign

    func testParseSignPayloadExtractsSignatureData() throws {
        let sig = Data([0xAA, 0xBB, 0xCC])
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeByteString(tag: Tag.SignatureData, value: sig),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseSignPayload(payload)
        XCTAssertEqual(result.signatureData, sig)
    }

    // MARK: - Response parsing -- SignatureVerify

    func testParseSignatureVerifyPayloadValid() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeEnum(tag: Tag.ValidityIndicator, value: 0), // 0 = valid
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseSignatureVerifyPayload(payload)
        XCTAssertTrue(result.valid)
    }

    func testParseSignatureVerifyPayloadInvalid() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeEnum(tag: Tag.ValidityIndicator, value: 1), // 1 = invalid
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseSignatureVerifyPayload(payload)
        XCTAssertFalse(result.valid)
    }

    // MARK: - Response parsing -- MAC

    func testParseMACPayloadExtractsMACData() throws {
        let macData = Data([0x11, 0x22, 0x33])
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeByteString(tag: Tag.MACData, value: macData),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseMACPayload(payload)
        XCTAssertEqual(result.macData, macData)
    }

    // MARK: - Response parsing -- Query

    func testParseQueryPayloadExtractsOperationsAndObjectTypes() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeEnum(tag: Tag.Operation, value: KmipOperation.Create),
            encodeEnum(tag: Tag.Operation, value: KmipOperation.Get),
            encodeEnum(tag: Tag.Operation, value: KmipOperation.Locate),
            encodeEnum(tag: Tag.ObjectType, value: KmipObjectType.SymmetricKey),
            encodeEnum(tag: Tag.ObjectType, value: KmipObjectType.PublicKey),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseQueryPayload(payload)
        XCTAssertEqual(result.operations, [KmipOperation.Create, KmipOperation.Get, KmipOperation.Locate])
        XCTAssertEqual(result.objectTypes, [KmipObjectType.SymmetricKey, KmipObjectType.PublicKey])
    }

    func testParseQueryPayloadHandlesEmpty() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [])
        let payload = try decodeTTLV(payloadData)
        let result = parseQueryPayload(payload)
        XCTAssertEqual(result.operations, [])
        XCTAssertEqual(result.objectTypes, [])
    }

    // MARK: - Response parsing -- DiscoverVersions

    func testParseDiscoverVersionsPayloadExtractsVersions() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [
            encodeStructure(tag: Tag.ProtocolVersion, children: [
                encodeInteger(tag: Tag.ProtocolVersionMajor, value: 1),
                encodeInteger(tag: Tag.ProtocolVersionMinor, value: 4),
            ]),
            encodeStructure(tag: Tag.ProtocolVersion, children: [
                encodeInteger(tag: Tag.ProtocolVersionMajor, value: 1),
                encodeInteger(tag: Tag.ProtocolVersionMinor, value: 2),
            ]),
        ])
        let payload = try decodeTTLV(payloadData)
        let result = parseDiscoverVersionsPayload(payload)
        XCTAssertEqual(result.versions.count, 2)
        XCTAssertEqual(result.versions[0].major, 1)
        XCTAssertEqual(result.versions[0].minor, 4)
        XCTAssertEqual(result.versions[1].major, 1)
        XCTAssertEqual(result.versions[1].minor, 2)
    }

    func testParseDiscoverVersionsPayloadHandlesEmpty() throws {
        let payloadData = encodeStructure(tag: Tag.ResponsePayload, children: [])
        let payload = try decodeTTLV(payloadData)
        let result = parseDiscoverVersionsPayload(payload)
        XCTAssertEqual(result.versions.count, 0)
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

    // MARK: - All 27 request builders produce valid TTLV

    func testAllRequestBuildersProduceValidTTLV() throws {
        let requests: [(String, Data)] = [
            ("Locate", buildLocateRequest(name: "k")),
            ("Get", buildGetRequest(uniqueId: "uid")),
            ("Create", buildCreateRequest(name: "k")),
            ("Activate", buildActivateRequest(uniqueId: "uid")),
            ("Destroy", buildDestroyRequest(uniqueId: "uid")),
            ("Check", buildCheckRequest(uniqueId: "uid")),
            ("CreateKeyPair", buildCreateKeyPairRequest(name: "k", algorithm: KmipAlgorithm.RSA, length: 2048)),
            ("Register", buildRegisterRequest(objectType: KmipObjectType.SymmetricKey, material: Data([0x01]), name: "k", algorithm: KmipAlgorithm.AES, length: 8)),
            ("ReKey", buildReKeyRequest(uniqueId: "uid")),
            ("DeriveKey", buildDeriveKeyRequest(uniqueId: "uid", derivationData: Data([0x01]), name: "dk", length: 256)),
            ("GetAttributes", buildGetAttributesRequest(uniqueId: "uid")),
            ("GetAttributeList", buildGetAttributeListRequest(uniqueId: "uid")),
            ("AddAttribute", buildAddAttributeRequest(uniqueId: "uid", attrName: "n", attrValue: "v")),
            ("ModifyAttribute", buildModifyAttributeRequest(uniqueId: "uid", attrName: "n", attrValue: "v")),
            ("DeleteAttribute", buildDeleteAttributeRequest(uniqueId: "uid", attrName: "n")),
            ("ObtainLease", buildObtainLeaseRequest(uniqueId: "uid")),
            ("Revoke", buildRevokeRequest(uniqueId: "uid", reason: 1)),
            ("Archive", buildArchiveRequest(uniqueId: "uid")),
            ("Recover", buildRecoverRequest(uniqueId: "uid")),
            ("Query", buildQueryRequest()),
            ("Poll", buildPollRequest()),
            ("DiscoverVersions", buildDiscoverVersionsRequest()),
            ("Encrypt", buildEncryptRequest(uniqueId: "uid", data: Data([0x01]))),
            ("Decrypt", buildDecryptRequest(uniqueId: "uid", data: Data([0x01]))),
            ("Sign", buildSignRequest(uniqueId: "uid", data: Data([0x01]))),
            ("SignatureVerify", buildSignatureVerifyRequest(uniqueId: "uid", data: Data([0x01]), signature: Data([0x02]))),
            ("MAC", buildMACRequest(uniqueId: "uid", data: Data([0x01]))),
        ]
        XCTAssertEqual(requests.count, 27, "Should test all 27 operations")
        for (name, request) in requests {
            let decoded = try decodeTTLV(request)
            XCTAssertEqual(decoded.tag, Tag.RequestMessage, "\(name) request should have RequestMessage tag")
        }
    }
}
