//
// Operations.swift
// CypheraKmip
//
// KMIP request/response builders for all 27 KMIP 1.4 operations.
//

import Foundation

// Protocol version: KMIP 1.4
public let PROTOCOL_MAJOR: Int32 = 1
public let PROTOCOL_MINOR: Int32 = 4

// MARK: - Request Header

/// Build the request header (included in every request).
func buildRequestHeader(batchCount: Int32 = 1) -> Data {
    return encodeStructure(tag: Tag.RequestHeader, children: [
        encodeStructure(tag: Tag.ProtocolVersion, children: [
            encodeInteger(tag: Tag.ProtocolVersionMajor, value: PROTOCOL_MAJOR),
            encodeInteger(tag: Tag.ProtocolVersionMinor, value: PROTOCOL_MINOR),
        ]),
        encodeInteger(tag: Tag.BatchCount, value: batchCount),
    ])
}

// MARK: - Internal Helpers

/// Build a request with just a UID in the payload.
func buildUIDOnlyRequest(operation: UInt32, uniqueId: String) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: operation),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a request with an empty payload.
func buildEmptyPayloadRequest(operation: UInt32) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: operation),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

// MARK: - Request Builders

/// Build a Locate request -- find keys by name.
public func buildLocateRequest(name: String) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeStructure(tag: Tag.Attribute, children: [
            encodeTextString(tag: Tag.AttributeName, value: "Name"),
            encodeStructure(tag: Tag.AttributeValue, children: [
                encodeTextString(tag: Tag.NameValue, value: name),
                encodeEnum(tag: Tag.NameType, value: KmipNameType.UninterpretedTextString),
            ]),
        ]),
    ])

    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Locate),
        payload,
    ])

    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a Get request -- fetch key material by unique ID.
public func buildGetRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.Get, uniqueId: uniqueId)
}

/// Build a Create request -- create a new symmetric key.
public func buildCreateRequest(name: String, algorithm: UInt32 = KmipAlgorithm.AES, length: Int32 = 256) -> Data {
    let usageMask = Int32(KmipUsageMask.Encrypt | KmipUsageMask.Decrypt)

    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeEnum(tag: Tag.ObjectType, value: KmipObjectType.SymmetricKey),
        encodeStructure(tag: Tag.TemplateAttribute, children: [
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Cryptographic Algorithm"),
                encodeEnum(tag: Tag.AttributeValue, value: algorithm),
            ]),
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Cryptographic Length"),
                encodeInteger(tag: Tag.AttributeValue, value: length),
            ]),
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Cryptographic Usage Mask"),
                encodeInteger(tag: Tag.AttributeValue, value: usageMask),
            ]),
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Name"),
                encodeStructure(tag: Tag.AttributeValue, children: [
                    encodeTextString(tag: Tag.NameValue, value: name),
                    encodeEnum(tag: Tag.NameType, value: KmipNameType.UninterpretedTextString),
                ]),
            ]),
        ]),
    ])

    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Create),
        payload,
    ])

    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build an Activate request.
public func buildActivateRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.Activate, uniqueId: uniqueId)
}

/// Build a Destroy request.
public func buildDestroyRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.Destroy, uniqueId: uniqueId)
}

/// Build a Check request.
public func buildCheckRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.Check, uniqueId: uniqueId)
}

/// Build a CreateKeyPair request.
public func buildCreateKeyPairRequest(name: String, algorithm: UInt32, length: Int32) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeStructure(tag: Tag.TemplateAttribute, children: [
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Cryptographic Algorithm"),
                encodeEnum(tag: Tag.AttributeValue, value: algorithm),
            ]),
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Cryptographic Length"),
                encodeInteger(tag: Tag.AttributeValue, value: length),
            ]),
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Cryptographic Usage Mask"),
                encodeInteger(tag: Tag.AttributeValue, value: Int32(KmipUsageMask.Sign | KmipUsageMask.Verify)),
            ]),
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Name"),
                encodeStructure(tag: Tag.AttributeValue, children: [
                    encodeTextString(tag: Tag.NameValue, value: name),
                    encodeEnum(tag: Tag.NameType, value: KmipNameType.UninterpretedTextString),
                ]),
            ]),
        ]),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.CreateKeyPair),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a Register request for a symmetric key.
public func buildRegisterRequest(objectType: UInt32, material: Data, name: String, algorithm: UInt32, length: Int32) -> Data {
    var payloadChildren: [Data] = [
        encodeEnum(tag: Tag.ObjectType, value: objectType),
        encodeStructure(tag: Tag.SymmetricKey, children: [
            encodeStructure(tag: Tag.KeyBlock, children: [
                encodeEnum(tag: Tag.KeyFormatType, value: KmipKeyFormatType.Raw),
                encodeStructure(tag: Tag.KeyValue, children: [
                    encodeByteString(tag: Tag.KeyMaterial, value: material),
                ]),
                encodeEnum(tag: Tag.CryptographicAlgorithm, value: algorithm),
                encodeInteger(tag: Tag.CryptographicLength, value: length),
            ]),
        ]),
    ]
    if !name.isEmpty {
        payloadChildren.append(
            encodeStructure(tag: Tag.TemplateAttribute, children: [
                encodeStructure(tag: Tag.Attribute, children: [
                    encodeTextString(tag: Tag.AttributeName, value: "Name"),
                    encodeStructure(tag: Tag.AttributeValue, children: [
                        encodeTextString(tag: Tag.NameValue, value: name),
                        encodeEnum(tag: Tag.NameType, value: KmipNameType.UninterpretedTextString),
                    ]),
                ]),
            ])
        )
    }
    let payload = encodeStructure(tag: Tag.RequestPayload, children: payloadChildren)
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Register),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a ReKey request.
public func buildReKeyRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.ReKey, uniqueId: uniqueId)
}

/// Build a DeriveKey request.
public func buildDeriveKeyRequest(uniqueId: String, derivationData: Data, name: String, length: Int32) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeStructure(tag: Tag.DerivationParameters, children: [
            encodeByteString(tag: Tag.DerivationData, value: derivationData),
        ]),
        encodeStructure(tag: Tag.TemplateAttribute, children: [
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Cryptographic Length"),
                encodeInteger(tag: Tag.AttributeValue, value: length),
            ]),
            encodeStructure(tag: Tag.Attribute, children: [
                encodeTextString(tag: Tag.AttributeName, value: "Name"),
                encodeStructure(tag: Tag.AttributeValue, children: [
                    encodeTextString(tag: Tag.NameValue, value: name),
                    encodeEnum(tag: Tag.NameType, value: KmipNameType.UninterpretedTextString),
                ]),
            ]),
        ]),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.DeriveKey),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a GetAttributes request.
public func buildGetAttributesRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.GetAttributes, uniqueId: uniqueId)
}

/// Build a GetAttributeList request.
public func buildGetAttributeListRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.GetAttributeList, uniqueId: uniqueId)
}

/// Build an AddAttribute request.
public func buildAddAttributeRequest(uniqueId: String, attrName: String, attrValue: String) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeStructure(tag: Tag.Attribute, children: [
            encodeTextString(tag: Tag.AttributeName, value: attrName),
            encodeTextString(tag: Tag.AttributeValue, value: attrValue),
        ]),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.AddAttribute),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a ModifyAttribute request.
public func buildModifyAttributeRequest(uniqueId: String, attrName: String, attrValue: String) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeStructure(tag: Tag.Attribute, children: [
            encodeTextString(tag: Tag.AttributeName, value: attrName),
            encodeTextString(tag: Tag.AttributeValue, value: attrValue),
        ]),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.ModifyAttribute),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a DeleteAttribute request.
public func buildDeleteAttributeRequest(uniqueId: String, attrName: String) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeStructure(tag: Tag.Attribute, children: [
            encodeTextString(tag: Tag.AttributeName, value: attrName),
        ]),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.DeleteAttribute),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build an ObtainLease request.
public func buildObtainLeaseRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.ObtainLease, uniqueId: uniqueId)
}

/// Build a Revoke request with a revocation reason.
public func buildRevokeRequest(uniqueId: String, reason: UInt32) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeStructure(tag: Tag.RevocationReason, children: [
            encodeEnum(tag: Tag.RevocationReasonCode, value: reason),
        ]),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Revoke),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build an Archive request.
public func buildArchiveRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.Archive, uniqueId: uniqueId)
}

/// Build a Recover request.
public func buildRecoverRequest(uniqueId: String) -> Data {
    return buildUIDOnlyRequest(operation: KmipOperation.Recover, uniqueId: uniqueId)
}

/// Build a Query request.
public func buildQueryRequest() -> Data {
    return buildEmptyPayloadRequest(operation: KmipOperation.Query)
}

/// Build a Poll request.
public func buildPollRequest() -> Data {
    return buildEmptyPayloadRequest(operation: KmipOperation.Poll)
}

/// Build a DiscoverVersions request.
public func buildDiscoverVersionsRequest() -> Data {
    return buildEmptyPayloadRequest(operation: KmipOperation.DiscoverVersions)
}

/// Build an Encrypt request.
public func buildEncryptRequest(uniqueId: String, data: Data) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeByteString(tag: Tag.Data, value: data),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Encrypt),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a Decrypt request.
public func buildDecryptRequest(uniqueId: String, data: Data, nonce: Data? = nil) -> Data {
    var payloadChildren: [Data] = [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeByteString(tag: Tag.Data, value: data),
    ]
    if let nonce = nonce, !nonce.isEmpty {
        payloadChildren.append(encodeByteString(tag: Tag.IVCounterNonce, value: nonce))
    }
    let payload = encodeStructure(tag: Tag.RequestPayload, children: payloadChildren)
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Decrypt),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a Sign request.
public func buildSignRequest(uniqueId: String, data: Data) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeByteString(tag: Tag.Data, value: data),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Sign),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a SignatureVerify request.
public func buildSignatureVerifyRequest(uniqueId: String, data: Data, signature: Data) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeByteString(tag: Tag.Data, value: data),
        encodeByteString(tag: Tag.SignatureData, value: signature),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.SignatureVerify),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

/// Build a MAC request.
public func buildMACRequest(uniqueId: String, data: Data) -> Data {
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
        encodeByteString(tag: Tag.Data, value: data),
    ])
    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.MAC),
        payload,
    ])
    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
}

// MARK: - Response Types

/// Parsed KMIP response.
public struct KmipResponse {
    public let operation: UInt32?
    public let resultStatus: UInt32?
    public let resultReason: UInt32?
    public let resultMessage: String?
    public let payload: TtlvItem?
}

/// Parse a KMIP response message.
public func parseResponse(_ data: Data) throws -> KmipResponse {
    let msg = try decodeTTLV(data)
    guard msg.tag == Tag.ResponseMessage else {
        throw KmipError.unexpectedTag(expected: Tag.ResponseMessage, got: msg.tag)
    }

    guard let batchItem = findChild(msg, tag: Tag.BatchItem) else {
        throw KmipError.noBatchItem
    }

    let operationItem = findChild(batchItem, tag: Tag.Operation)
    let statusItem = findChild(batchItem, tag: Tag.ResultStatus)
    let reasonItem = findChild(batchItem, tag: Tag.ResultReason)
    let messageItem = findChild(batchItem, tag: Tag.ResultMessage)
    let payloadItem = findChild(batchItem, tag: Tag.ResponsePayload)

    let operation: UInt32? = {
        if case .enumeration(let v) = operationItem?.value { return v }
        return nil
    }()

    let status: UInt32? = {
        if case .enumeration(let v) = statusItem?.value { return v }
        return nil
    }()

    let reason: UInt32? = {
        if case .enumeration(let v) = reasonItem?.value { return v }
        return nil
    }()

    let message: String? = {
        if case .textString(let v) = messageItem?.value { return v }
        return nil
    }()

    if status != KmipResultStatus.Success {
        let errorMsg = message ?? "KMIP operation failed (status=\(status ?? 0))"
        throw KmipError.operationFailed(message: errorMsg, status: status, reason: reason)
    }

    return KmipResponse(
        operation: operation,
        resultStatus: status,
        resultReason: reason,
        resultMessage: message,
        payload: payloadItem
    )
}

// MARK: - Locate

/// Parsed Locate response.
public struct LocateResult {
    public let uniqueIdentifiers: [String]
}

public func parseLocatePayload(_ payload: TtlvItem) -> LocateResult {
    let ids = findChildren(payload, tag: Tag.UniqueIdentifier)
    let identifiers = ids.compactMap { item -> String? in
        if case .textString(let v) = item.value { return v }
        return nil
    }
    return LocateResult(uniqueIdentifiers: identifiers)
}

// MARK: - Get

/// Parsed Get response.
public struct GetResult {
    public let objectType: UInt32?
    public let uniqueIdentifier: String?
    public let keyMaterial: Data?
}

public func parseGetPayload(_ payload: TtlvItem) -> GetResult {
    let uid: String? = {
        if let item = findChild(payload, tag: Tag.UniqueIdentifier),
           case .textString(let v) = item.value { return v }
        return nil
    }()

    let objType: UInt32? = {
        if let item = findChild(payload, tag: Tag.ObjectType),
           case .enumeration(let v) = item.value { return v }
        return nil
    }()

    // Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
    var keyMaterial: Data? = nil
    if let symKey = findChild(payload, tag: Tag.SymmetricKey),
       let keyBlock = findChild(symKey, tag: Tag.KeyBlock),
       let keyValue = findChild(keyBlock, tag: Tag.KeyValue),
       let material = findChild(keyValue, tag: Tag.KeyMaterial) {
        if case .byteString(let v) = material.value {
            keyMaterial = v
        }
    }

    return GetResult(objectType: objType, uniqueIdentifier: uid, keyMaterial: keyMaterial)
}

// MARK: - Create

/// Parsed Create response.
public struct CreateResult {
    public let objectType: UInt32?
    public let uniqueIdentifier: String?
}

public func parseCreatePayload(_ payload: TtlvItem) -> CreateResult {
    let uid: String? = {
        if let item = findChild(payload, tag: Tag.UniqueIdentifier),
           case .textString(let v) = item.value { return v }
        return nil
    }()

    let objType: UInt32? = {
        if let item = findChild(payload, tag: Tag.ObjectType),
           case .enumeration(let v) = item.value { return v }
        return nil
    }()

    return CreateResult(objectType: objType, uniqueIdentifier: uid)
}

// MARK: - Check

/// Parsed Check response.
public struct CheckResult {
    public let uniqueIdentifier: String?
}

public func parseCheckPayload(_ payload: TtlvItem) -> CheckResult {
    let uid: String? = {
        if let item = findChild(payload, tag: Tag.UniqueIdentifier),
           case .textString(let v) = item.value { return v }
        return nil
    }()
    return CheckResult(uniqueIdentifier: uid)
}

// MARK: - ReKey

/// Parsed ReKey response.
public struct ReKeyResult {
    public let uniqueIdentifier: String?
}

public func parseReKeyPayload(_ payload: TtlvItem) -> ReKeyResult {
    let uid: String? = {
        if let item = findChild(payload, tag: Tag.UniqueIdentifier),
           case .textString(let v) = item.value { return v }
        return nil
    }()
    return ReKeyResult(uniqueIdentifier: uid)
}

// MARK: - CreateKeyPair

/// Parsed CreateKeyPair response.
public struct CreateKeyPairResult {
    public let privateKeyUID: String?
    public let publicKeyUID: String?
}

public func parseCreateKeyPairPayload(_ payload: TtlvItem) -> CreateKeyPairResult {
    let privUID: String? = {
        if let item = findChild(payload, tag: Tag.PrivateKeyUniqueIdentifier),
           case .textString(let v) = item.value { return v }
        return nil
    }()
    let pubUID: String? = {
        if let item = findChild(payload, tag: Tag.PublicKeyUniqueIdentifier),
           case .textString(let v) = item.value { return v }
        return nil
    }()
    return CreateKeyPairResult(privateKeyUID: privUID, publicKeyUID: pubUID)
}

// MARK: - DeriveKey

/// Parsed DeriveKey response.
public struct DeriveKeyResult {
    public let uniqueIdentifier: String?
}

public func parseDeriveKeyPayload(_ payload: TtlvItem) -> DeriveKeyResult {
    let uid: String? = {
        if let item = findChild(payload, tag: Tag.UniqueIdentifier),
           case .textString(let v) = item.value { return v }
        return nil
    }()
    return DeriveKeyResult(uniqueIdentifier: uid)
}

// MARK: - Encrypt

/// Parsed Encrypt response.
public struct EncryptResult {
    public let data: Data?
    public let nonce: Data?
}

public func parseEncryptPayload(_ payload: TtlvItem) -> EncryptResult {
    let data: Data? = {
        if let item = findChild(payload, tag: Tag.Data),
           case .byteString(let v) = item.value { return v }
        return nil
    }()
    let nonce: Data? = {
        if let item = findChild(payload, tag: Tag.IVCounterNonce),
           case .byteString(let v) = item.value { return v }
        return nil
    }()
    return EncryptResult(data: data, nonce: nonce)
}

// MARK: - Decrypt

/// Parsed Decrypt response.
public struct DecryptResult {
    public let data: Data?
}

public func parseDecryptPayload(_ payload: TtlvItem) -> DecryptResult {
    let data: Data? = {
        if let item = findChild(payload, tag: Tag.Data),
           case .byteString(let v) = item.value { return v }
        return nil
    }()
    return DecryptResult(data: data)
}

// MARK: - Sign

/// Parsed Sign response.
public struct SignResult {
    public let signatureData: Data?
}

public func parseSignPayload(_ payload: TtlvItem) -> SignResult {
    let sig: Data? = {
        if let item = findChild(payload, tag: Tag.SignatureData),
           case .byteString(let v) = item.value { return v }
        return nil
    }()
    return SignResult(signatureData: sig)
}

// MARK: - SignatureVerify

/// Parsed SignatureVerify response.
public struct SignatureVerifyResult {
    public let valid: Bool
}

public func parseSignatureVerifyPayload(_ payload: TtlvItem) -> SignatureVerifyResult {
    if let indicator = findChild(payload, tag: Tag.ValidityIndicator) {
        if case .enumeration(let v) = indicator.value {
            // 0 = Valid, 1 = Invalid
            return SignatureVerifyResult(valid: v == 0)
        }
    }
    return SignatureVerifyResult(valid: false)
}

// MARK: - MAC

/// Parsed MAC response.
public struct MACResult {
    public let macData: Data?
}

public func parseMACPayload(_ payload: TtlvItem) -> MACResult {
    let data: Data? = {
        if let item = findChild(payload, tag: Tag.MACData),
           case .byteString(let v) = item.value { return v }
        return nil
    }()
    return MACResult(macData: data)
}

// MARK: - Query

/// Parsed Query response.
public struct QueryResult {
    public let operations: [UInt32]
    public let objectTypes: [UInt32]
}

public func parseQueryPayload(_ payload: TtlvItem) -> QueryResult {
    let ops = findChildren(payload, tag: Tag.Operation).compactMap { item -> UInt32? in
        if case .enumeration(let v) = item.value { return v }
        return nil
    }
    let objTypes = findChildren(payload, tag: Tag.ObjectType).compactMap { item -> UInt32? in
        if case .enumeration(let v) = item.value { return v }
        return nil
    }
    return QueryResult(operations: ops, objectTypes: objTypes)
}

// MARK: - DiscoverVersions

/// Parsed DiscoverVersions response.
public struct DiscoverVersionsResult {
    public struct Version {
        public let major: Int32
        public let minor: Int32
    }
    public let versions: [Version]
}

public func parseDiscoverVersionsPayload(_ payload: TtlvItem) -> DiscoverVersionsResult {
    let versionItems = findChildren(payload, tag: Tag.ProtocolVersion)
    let versions = versionItems.compactMap { v -> DiscoverVersionsResult.Version? in
        var major: Int32 = 0
        var minor: Int32 = 0
        if let majorItem = findChild(v, tag: Tag.ProtocolVersionMajor),
           case .integer(let m) = majorItem.value {
            major = m
        }
        if let minorItem = findChild(v, tag: Tag.ProtocolVersionMinor),
           case .integer(let m) = minorItem.value {
            minor = m
        }
        return DiscoverVersionsResult.Version(major: major, minor: minor)
    }
    return DiscoverVersionsResult(versions: versions)
}

// MARK: - Errors

/// KMIP errors.
public enum KmipError: Error {
    case unexpectedTag(expected: UInt32, got: UInt32)
    case noBatchItem
    case operationFailed(message: String, status: UInt32?, reason: UInt32?)
    case connectionFailed(String)
    case noKeyFound(String)
    case noKeyMaterial(String)
}

// MARK: - Algorithm Resolution

/// Convert an algorithm name string to its KMIP enum value.
/// Returns 0 for unknown algorithms.
public func resolveAlgorithm(_ name: String) -> UInt32 {
    switch name.uppercased() {
    case "AES":        return KmipAlgorithm.AES
    case "DES":        return KmipAlgorithm.DES
    case "TRIPLEDES", "3DES": return KmipAlgorithm.TripleDES
    case "RSA":        return KmipAlgorithm.RSA
    case "DSA":        return KmipAlgorithm.DSA
    case "ECDSA":      return KmipAlgorithm.ECDSA
    case "HMACSHA1":   return KmipAlgorithm.HMACSHA1
    case "HMACSHA256": return KmipAlgorithm.HMACSHA256
    case "HMACSHA384": return KmipAlgorithm.HMACSHA384
    case "HMACSHA512": return KmipAlgorithm.HMACSHA512
    default:           return 0
    }
}
