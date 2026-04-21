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
    let val: Int64 = value ? 1 : 0
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

/// Maximum length accepted for a single TTLV item's declared length field.
/// Larger values are rejected before any arithmetic is performed to avoid overflow.
/// Matches the 16 MiB response ceiling in KmipClient.
private let maxItemLength = 16 * 1024 * 1024

/// Maximum number of direct children permitted in a Structure node.
private let maxStructureChildren = 10_000

/// Decode a TTLV buffer into a parsed tree.
public func decodeTTLV(_ buf: Data, offset: Int = 0) throws -> TtlvItem {
    return try decodeTTLVDepth(buf, offset: offset, depth: 0)
}

private func decodeTTLVDepth(_ buf: Data, offset: Int, depth: Int) throws -> TtlvItem {
    guard depth <= maxDecodeDepth else {
        throw TtlvError.maxDepthExceeded
    }

    guard offset >= 0, buf.count - offset >= 8 else {
        throw TtlvError.bufferTooShort
    }

    let base = buf.startIndex + offset
    let tag: UInt32 = (UInt32(buf[base]) << 16) | (UInt32(buf[base + 1]) << 8) | UInt32(buf[base + 2])
    let type = buf[base + 3]
    let rawLength: UInt32 =
        (UInt32(buf[base + 4]) << 24) |
        (UInt32(buf[base + 5]) << 16) |
        (UInt32(buf[base + 6]) << 8) |
        UInt32(buf[base + 7])

    // Reject lengths that would overflow Int or exceed any plausible message size
    // before doing any padding arithmetic.
    guard rawLength <= UInt32(maxItemLength) else {
        throw TtlvError.lengthExceedsLimit(declared: Int64(rawLength), limit: maxItemLength)
    }
    let length = Int(rawLength)
    let padded = ((length + 7) / 8) * 8
    let totalLength = 8 + padded
    let valueStart = offset + 8

    // Bounds check: ensure declared (padded) length fits within buffer and
    // valueStart + padded does not overflow.
    let (valueEndUnpadded, endOverflow) = valueStart.addingReportingOverflow(length)
    guard !endOverflow else {
        throw TtlvError.integerOverflow
    }
    guard valueStart + padded <= buf.count else {
        throw TtlvError.lengthExceedsBuffer(declared: length, available: buf.count - valueStart)
    }

    let value: TtlvValue

    switch type {
    case TtlvType.structure.rawValue:
        var children: [TtlvItem] = []
        var pos = valueStart
        let end = valueEndUnpadded
        while pos < end {
            let child = try decodeTTLVDepth(buf, offset: pos, depth: depth + 1)
            let (newPos, posOverflow) = pos.addingReportingOverflow(child.totalLength)
            guard !posOverflow, newPos <= end else {
                throw TtlvError.childExceedsStructure
            }
            guard children.count < maxStructureChildren else {
                throw TtlvError.tooManyChildren(limit: maxStructureChildren)
            }
            children.append(child)
            pos = newPos
        }
        value = .structure(children)

    case TtlvType.integer.rawValue:
        guard length == 4 else {
            throw TtlvError.invalidLength(type: type, expected: 4, actual: length)
        }
        let raw = try readInt32BE(buf, offset: valueStart)
        value = .integer(raw)

    case TtlvType.longInteger.rawValue:
        guard length == 8 else {
            throw TtlvError.invalidLength(type: type, expected: 8, actual: length)
        }
        let raw = try readInt64BE(buf, offset: valueStart)
        value = .longInteger(raw)

    case TtlvType.enumeration.rawValue:
        guard length == 4 else {
            throw TtlvError.invalidLength(type: type, expected: 4, actual: length)
        }
        let raw = try readUInt32BE(buf, offset: valueStart)
        value = .enumeration(raw)

    case TtlvType.boolean.rawValue:
        guard length == 8 else {
            throw TtlvError.invalidLength(type: type, expected: 8, actual: length)
        }
        let raw = try readInt64BE(buf, offset: valueStart)
        value = .boolean(raw != 0)

    case TtlvType.textString.rawValue:
        let strStart = buf.startIndex + valueStart
        let strData = buf.subdata(in: strStart..<(strStart + length))
        guard let str = String(data: strData, encoding: .utf8) else {
            throw TtlvError.invalidUTF8(offset: valueStart)
        }
        value = .textString(str)

    case TtlvType.byteString.rawValue:
        let bsStart = buf.startIndex + valueStart
        value = .byteString(buf.subdata(in: bsStart..<(bsStart + length)))

    case TtlvType.dateTime.rawValue:
        guard length == 8 else {
            throw TtlvError.invalidLength(type: type, expected: 8, actual: length)
        }
        let raw = try readInt64BE(buf, offset: valueStart)
        value = .dateTime(raw)

    default:
        let rawStart = buf.startIndex + valueStart
        value = .raw(buf.subdata(in: rawStart..<(rawStart + length)))
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

public enum TtlvError: Error, Equatable {
    case bufferTooShort
    case lengthExceedsBuffer(declared: Int, available: Int)
    case lengthExceedsLimit(declared: Int64, limit: Int)
    case maxDepthExceeded
    case invalidLength(type: UInt8, expected: Int, actual: Int)
    case invalidUTF8(offset: Int)
    case integerOverflow
    case childExceedsStructure
    case tooManyChildren(limit: Int)
}

// MARK: - Helpers

private func readInt32BE(_ data: Data, offset: Int) throws -> Int32 {
    let base = data.startIndex + offset
    guard offset >= 0, offset + 3 < data.count else {
        throw TtlvError.bufferTooShort
    }
    let raw: UInt32 = (UInt32(data[base]) << 24) |
        (UInt32(data[base + 1]) << 16) |
        (UInt32(data[base + 2]) << 8) |
        UInt32(data[base + 3])
    return Int32(bitPattern: raw)
}

private func readUInt32BE(_ data: Data, offset: Int) throws -> UInt32 {
    let base = data.startIndex + offset
    guard offset >= 0, offset + 3 < data.count else {
        throw TtlvError.bufferTooShort
    }
    return (UInt32(data[base]) << 24) |
        (UInt32(data[base + 1]) << 16) |
        (UInt32(data[base + 2]) << 8) |
        UInt32(data[base + 3])
}

private func readInt64BE(_ data: Data, offset: Int) throws -> Int64 {
    let base = data.startIndex + offset
    guard offset >= 0, offset + 7 < data.count else {
        throw TtlvError.bufferTooShort
    }
    var raw: UInt64 = 0
    raw |= UInt64(data[base])     << 56
    raw |= UInt64(data[base + 1]) << 48
    raw |= UInt64(data[base + 2]) << 40
    raw |= UInt64(data[base + 3]) << 32
    raw |= UInt64(data[base + 4]) << 24
    raw |= UInt64(data[base + 5]) << 16
    raw |= UInt64(data[base + 6]) << 8
    raw |= UInt64(data[base + 7])
    return Int64(bitPattern: raw)
}
