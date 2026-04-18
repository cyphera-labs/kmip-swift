//
// Operations.swift
// CypheraKmip
//
// KMIP request/response builders for Locate, Get, Create operations.
//

import Foundation

// Protocol version: KMIP 1.4
public let PROTOCOL_MAJOR: Int32 = 1
public let PROTOCOL_MINOR: Int32 = 4

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
    let payload = encodeStructure(tag: Tag.RequestPayload, children: [
        encodeTextString(tag: Tag.UniqueIdentifier, value: uniqueId),
    ])

    let batchItem = encodeStructure(tag: Tag.BatchItem, children: [
        encodeEnum(tag: Tag.Operation, value: KmipOperation.Get),
        payload,
    ])

    return encodeStructure(tag: Tag.RequestMessage, children: [
        buildRequestHeader(),
        batchItem,
    ])
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

/// Parse a Locate response payload.
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

/// Parse a Get response payload.
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

/// Parse a Create response payload.
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

/// KMIP errors.
public enum KmipError: Error {
    case unexpectedTag(expected: UInt32, got: UInt32)
    case noBatchItem
    case operationFailed(message: String, status: UInt32?, reason: UInt32?)
    case connectionFailed(String)
    case noKeyFound(String)
    case noKeyMaterial(String)
}
