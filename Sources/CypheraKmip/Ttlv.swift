//
// Ttlv.swift
// CypheraKmip
//
// TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
// Implements the OASIS KMIP 1.4 binary encoding.
//
// Each TTLV item:
//   Tag:    3 bytes (identifies the field)
//   Type:   1 byte  (data type)
//   Length: 4 bytes  (value length in bytes)
//   Value:  variable (padded to 8-byte alignment)
//

import Foundation

/// KMIP data types.
public enum TtlvType: UInt8 {
    case structure   = 0x01
    case integer     = 0x02
    case longInteger = 0x03
    case bigInteger  = 0x04
    case enumeration = 0x05
    case boolean     = 0x06
    case textString  = 0x07
    case byteString  = 0x08
    case dateTime    = 0x09
    case interval    = 0x0A
}

/// A decoded TTLV item.
public struct TtlvItem {
    public let tag: UInt32
    public let type: UInt8
    public let value: TtlvValue
    public let length: Int
    public let totalLength: Int
}

/// Possible decoded values.
public enum TtlvValue {
    case structure([TtlvItem])
    case integer(Int32)
    case longInteger(Int64)
    case enumeration(UInt32)
    case boolean(Bool)
    case textString(String)
    case byteString(Data)
    case dateTime(Int64)
    case raw(Data)
}

// MARK: - Encoding

/// Encode a single TTLV item to Data.
public func encodeTTLV(tag: UInt32, type: UInt8, value: Data) -> Data {
    let valueLen = value.count
    let padded = ((valueLen + 7) / 8) * 8
    var buf = Data(count: 8 + padded)

    // Tag: 3 bytes big-endian
    buf[0] = UInt8((tag >> 16) & 0xFF)
    buf[1] = UInt8((tag >> 8) & 0xFF)
    buf[2] = UInt8(tag & 0xFF)

    // Type: 1 byte
    buf[3] = type

    // Length: 4 bytes big-endian
    buf[4] = UInt8((UInt32(valueLen) >> 24) & 0xFF)
    buf[5] = UInt8((UInt32(valueLen) >> 16) & 0xFF)
    buf[6] = UInt8((UInt32(valueLen) >> 8) & 0xFF)
    buf[7] = UInt8(UInt32(valueLen) & 0xFF)

    // Value + padding (padding bytes remain zero)
    buf.replaceSubrange(8..<(8 + valueLen), with: value)

    return buf
}

/// Encode a Structure (type 0x01) containing child TTLV items.
public func encodeStructure(tag: UInt32, children: [Data]) -> Data {
    var inner = Data()
    for child in children {
        inner.append(child)
    }
    return encodeTTLV(tag: tag, type: TtlvType.structure.rawValue, value: inner)
}

/// Encode a 32-bit integer.
public func encodeInteger(tag: UInt32, value: Int32) -> Data {
    var bigEndian = value.bigEndian
    let data = Data(bytes: &bigEndian, count: 4)
    return encodeTTLV(tag: tag, type: TtlvType.integer.rawValue, value: data)
}

/// Encode a 64-bit long integer.
public func encodeLongInteger(tag: UInt32, value: Int64) -> Data {
    var bigEndian = value.bigEndian
    let data = Data(bytes: &bigEndian, count: 8)
    return encodeTTLV(tag: tag, type: TtlvType.longInteger.rawValue, value: data)
}

/// Encode an enumeration (32-bit unsigned).
public func encodeEnum(tag: UInt32, value: UInt32) -> Data {
    var bigEndian = value.bigEndian
    let data = Data(bytes: &bigEndian, count: 4)
    return encodeTTLV(tag: tag, type: TtlvType.enumeration.rawValue, value: data)
}

/// Encode a boolean.
public func encodeBoolean(tag: UInt32, value: Bool) -> Data {
    var val: Int64 = value ? 1 : 0
    var bigEndian = val.bigEndian
    let data = Data(bytes: &bigEndian, count: 8)
    return encodeTTLV(tag: tag, type: TtlvType.boolean.rawValue, value: data)
}

/// Encode a text string (UTF-8).
public func encodeTextString(tag: UInt32, value: String) -> Data {
    let data = value.data(using: .utf8) ?? Data()
    return encodeTTLV(tag: tag, type: TtlvType.textString.rawValue, value: data)
}

/// Encode a byte string (raw bytes).
public func encodeByteString(tag: UInt32, value: Data) -> Data {
    return encodeTTLV(tag: tag, type: TtlvType.byteString.rawValue, value: value)
}

/// Encode a DateTime (64-bit POSIX timestamp).
public func encodeDateTime(tag: UInt32, value: Int64) -> Data {
    var bigEndian = value.bigEndian
    let data = Data(bytes: &bigEndian, count: 8)
    return encodeTTLV(tag: tag, type: TtlvType.dateTime.rawValue, value: data)
}

// MARK: - Decoding

/// Maximum nesting depth for TTLV structures.
private let maxDecodeDepth = 32

/// Decode a TTLV buffer into a parsed tree.
public func decodeTTLV(_ buf: Data, offset: Int = 0) throws -> TtlvItem {
    return try decodeTTLVDepth(buf, offset: offset, depth: 0)
}

private func decodeTTLVDepth(_ buf: Data, offset: Int, depth: Int) throws -> TtlvItem {
    guard depth <= maxDecodeDepth else {
        throw TtlvError.maxDepthExceeded
    }

    guard buf.count - offset >= 8 else {
        throw TtlvError.bufferTooShort
    }

    let tag: UInt32 = (UInt32(buf[offset]) << 16) | (UInt32(buf[offset + 1]) << 8) | UInt32(buf[offset + 2])
    let type = buf[offset + 3]
    let length = Int(
        (UInt32(buf[offset + 4]) << 24) |
        (UInt32(buf[offset + 5]) << 16) |
        (UInt32(buf[offset + 6]) << 8) |
        UInt32(buf[offset + 7])
    )
    let padded = ((length + 7) / 8) * 8
    let totalLength = 8 + padded
    let valueStart = offset + 8

    // Bounds check: ensure declared length fits within buffer.
    guard valueStart + padded <= buf.count else {
        throw TtlvError.lengthExceedsBuffer(declared: length, available: buf.count - valueStart)
    }

    let value: TtlvValue

    switch type {
    case TtlvType.structure.rawValue:
        var children: [TtlvItem] = []
        var pos = valueStart
        let end = valueStart + length
        while pos < end {
            let child = try decodeTTLVDepth(buf, offset: pos, depth: depth + 1)
            children.append(child)
            pos += child.totalLength
        }
        value = .structure(children)

    case TtlvType.integer.rawValue:
        let raw = readInt32BE(buf, offset: valueStart)
        value = .integer(raw)

    case TtlvType.longInteger.rawValue:
        let raw = readInt64BE(buf, offset: valueStart)
        value = .longInteger(raw)

    case TtlvType.enumeration.rawValue:
        let raw = readUInt32BE(buf, offset: valueStart)
        value = .enumeration(raw)

    case TtlvType.boolean.rawValue:
        let raw = readInt64BE(buf, offset: valueStart)
        value = .boolean(raw != 0)

    case TtlvType.textString.rawValue:
        let strData = buf.subdata(in: valueStart..<(valueStart + length))
        value = .textString(String(data: strData, encoding: .utf8) ?? "")

    case TtlvType.byteString.rawValue:
        value = .byteString(buf.subdata(in: valueStart..<(valueStart + length)))

    case TtlvType.dateTime.rawValue:
        let raw = readInt64BE(buf, offset: valueStart)
        value = .dateTime(raw)

    default:
        value = .raw(buf.subdata(in: valueStart..<(valueStart + length)))
    }

    return TtlvItem(tag: tag, type: type, value: value, length: length, totalLength: totalLength)
}

/// Find a child item by tag within a decoded structure.
public func findChild(_ decoded: TtlvItem, tag: UInt32) -> TtlvItem? {
    guard case .structure(let children) = decoded.value else { return nil }
    return children.first { $0.tag == tag }
}

/// Find all children by tag within a decoded structure.
public func findChildren(_ decoded: TtlvItem, tag: UInt32) -> [TtlvItem] {
    guard case .structure(let children) = decoded.value else { return [] }
    return children.filter { $0.tag == tag }
}

// MARK: - Errors

public enum TtlvError: Error {
    case bufferTooShort
    case lengthExceedsBuffer(declared: Int, available: Int)
    case maxDepthExceeded
}

// MARK: - Helpers

private func readInt32BE(_ data: Data, offset: Int) -> Int32 {
    let raw: UInt32 = (UInt32(data[offset]) << 24) |
        (UInt32(data[offset + 1]) << 16) |
        (UInt32(data[offset + 2]) << 8) |
        UInt32(data[offset + 3])
    return Int32(bitPattern: raw)
}

private func readUInt32BE(_ data: Data, offset: Int) -> UInt32 {
    return (UInt32(data[offset]) << 24) |
        (UInt32(data[offset + 1]) << 16) |
        (UInt32(data[offset + 2]) << 8) |
        UInt32(data[offset + 3])
}

private func readInt64BE(_ data: Data, offset: Int) -> Int64 {
    var raw: UInt64 = 0
    raw |= UInt64(data[offset])     << 56
    raw |= UInt64(data[offset + 1]) << 48
    raw |= UInt64(data[offset + 2]) << 40
    raw |= UInt64(data[offset + 3]) << 32
    raw |= UInt64(data[offset + 4]) << 24
    raw |= UInt64(data[offset + 5]) << 16
    raw |= UInt64(data[offset + 6]) << 8
    raw |= UInt64(data[offset + 7])
    return Int64(bitPattern: raw)
}
