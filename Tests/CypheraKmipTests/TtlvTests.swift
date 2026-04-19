//
// TtlvTests.swift
// CypheraKmipTests
//
// Comprehensive TTLV codec tests: primitives, padding, structures,
// navigation, wire format, error handling, unicode.
//

import XCTest
@testable import CypheraKmip

final class TtlvTests: XCTestCase {

    // MARK: - Primitive encode / decode round-trips

    func testEncodeDecodeInteger() throws {
        let encoded = encodeInteger(tag: 0x42006A, value: 1)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.tag, 0x42006A)
        XCTAssertEqual(decoded.type, TtlvType.integer.rawValue)
        if case .integer(let v) = decoded.value {
            XCTAssertEqual(v, 1)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testEncodeDecodeNegativeInteger() throws {
        let encoded = encodeInteger(tag: 0x42006A, value: -42)
        let decoded = try decodeTTLV(encoded)
        if case .integer(let v) = decoded.value {
            XCTAssertEqual(v, -42)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testEncodeDecodeMaxInt32() throws {
        let encoded = encodeInteger(tag: 0x42006A, value: Int32.max)
        let decoded = try decodeTTLV(encoded)
        if case .integer(let v) = decoded.value {
            XCTAssertEqual(v, Int32.max)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testEncodeDecodeMinInt32() throws {
        let encoded = encodeInteger(tag: 0x42006A, value: Int32.min)
        let decoded = try decodeTTLV(encoded)
        if case .integer(let v) = decoded.value {
            XCTAssertEqual(v, Int32.min)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testEncodeDecodeZeroInteger() throws {
        let encoded = encodeInteger(tag: 0x42006A, value: 0)
        let decoded = try decodeTTLV(encoded)
        if case .integer(let v) = decoded.value {
            XCTAssertEqual(v, 0)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testEncodeDecodeEnumeration() throws {
        let encoded = encodeEnum(tag: 0x42005C, value: 0x0000000A)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.tag, 0x42005C)
        XCTAssertEqual(decoded.type, TtlvType.enumeration.rawValue)
        if case .enumeration(let v) = decoded.value {
            XCTAssertEqual(v, 0x0000000A)
        } else {
            XCTFail("Expected enumeration value")
        }
    }

    func testEncodeDecodeLongInteger() throws {
        let encoded = encodeLongInteger(tag: 0x42006A, value: 1234567890123)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.tag, 0x42006A)
        XCTAssertEqual(decoded.type, TtlvType.longInteger.rawValue)
        if case .longInteger(let v) = decoded.value {
            XCTAssertEqual(v, 1234567890123)
        } else {
            XCTFail("Expected long integer value")
        }
    }

    func testEncodeDecodeNegativeLongInteger() throws {
        let encoded = encodeLongInteger(tag: 0x42006A, value: -9999999999)
        let decoded = try decodeTTLV(encoded)
        if case .longInteger(let v) = decoded.value {
            XCTAssertEqual(v, -9999999999)
        } else {
            XCTFail("Expected long integer value")
        }
    }

    func testEncodeDecodeTextString() throws {
        let encoded = encodeTextString(tag: 0x420055, value: "my-key")
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.tag, 0x420055)
        XCTAssertEqual(decoded.type, TtlvType.textString.rawValue)
        if case .textString(let v) = decoded.value {
            XCTAssertEqual(v, "my-key")
        } else {
            XCTFail("Expected text string value")
        }
    }

    func testEncodeDecodeByteString() throws {
        let key = Data([0xAA, 0xBB, 0xCC, 0xDD])
        let encoded = encodeByteString(tag: 0x420043, value: key)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.tag, 0x420043)
        XCTAssertEqual(decoded.type, TtlvType.byteString.rawValue)
        if case .byteString(let v) = decoded.value {
            XCTAssertEqual(v, key)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    func testEncodeDecodeBooleanTrue() throws {
        let encoded = encodeBoolean(tag: 0x420008, value: true)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.type, TtlvType.boolean.rawValue)
        if case .boolean(let v) = decoded.value {
            XCTAssertTrue(v)
        } else {
            XCTFail("Expected boolean value")
        }
    }

    func testEncodeDecodeBooleanFalse() throws {
        let encoded = encodeBoolean(tag: 0x420008, value: false)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.type, TtlvType.boolean.rawValue)
        if case .boolean(let v) = decoded.value {
            XCTAssertFalse(v)
        } else {
            XCTFail("Expected boolean value")
        }
    }

    func testEncodeDecodeDateTime() throws {
        let timestamp: Int64 = 1_776_700_800 // 2026-04-18T12:00:00Z approx
        let encoded = encodeDateTime(tag: 0x420008, value: timestamp)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.type, TtlvType.dateTime.rawValue)
        if case .dateTime(let v) = decoded.value {
            XCTAssertEqual(v, timestamp)
        } else {
            XCTFail("Expected dateTime value")
        }
    }

    func testEncodeDecodeEpochZeroDateTime() throws {
        let encoded = encodeDateTime(tag: 0x420008, value: 0)
        let decoded = try decodeTTLV(encoded)
        if case .dateTime(let v) = decoded.value {
            XCTAssertEqual(v, 0)
        } else {
            XCTFail("Expected dateTime value")
        }
    }

    // MARK: - Padding and alignment

    func testIntegerOccupies16BytesTotal() {
        let encoded = encodeInteger(tag: 0x42006A, value: 1)
        // 8 header + 8 padded value = 16 bytes
        XCTAssertEqual(encoded.count, 16)
        // Length field at offset 4..7 should say 4
        let length = readLengthField(encoded)
        XCTAssertEqual(length, 4)
    }

    func testEnumOccupies16BytesTotal() {
        let encoded = encodeEnum(tag: 0x42005C, value: 1)
        XCTAssertEqual(encoded.count, 16)
        XCTAssertEqual(readLengthField(encoded), 4)
    }

    func testBooleanUses8ByteValue() {
        let encoded = encodeBoolean(tag: 0x420008, value: true)
        XCTAssertEqual(encoded.count, 16) // 8 header + 8 value
        XCTAssertEqual(readLengthField(encoded), 8)
    }

    func testLongIntegerUses8ByteValue() {
        let encoded = encodeLongInteger(tag: 0x42006A, value: 42)
        XCTAssertEqual(encoded.count, 16)
        XCTAssertEqual(readLengthField(encoded), 8)
    }

    func testTextStringPadding5Bytes() {
        // "hello" = 5 bytes -> padded to 8 -> total = 16
        let encoded = encodeTextString(tag: 0x420055, value: "hello")
        XCTAssertEqual(encoded.count, 16)
    }

    func testTextStringExact8BytesNoPadding() {
        let encoded = encodeTextString(tag: 0x420055, value: "12345678")
        XCTAssertEqual(encoded.count, 16) // 8 header + 8 value
    }

    func testTextString9BytesPadsTo16() {
        let encoded = encodeTextString(tag: 0x420055, value: "123456789")
        XCTAssertEqual(encoded.count, 24) // 8 header + 16 padded
    }

    func testEmptyTextString() throws {
        let encoded = encodeTextString(tag: 0x420055, value: "")
        XCTAssertEqual(encoded.count, 8) // header only
        let decoded = try decodeTTLV(encoded)
        if case .textString(let v) = decoded.value {
            XCTAssertEqual(v, "")
        } else {
            XCTFail("Expected text string value")
        }
    }

    func testByteStringExact8ByteAlignment() {
        let data = Data(repeating: 0xAB, count: 16)
        let encoded = encodeByteString(tag: 0x420043, value: data)
        XCTAssertEqual(encoded.count, 24) // 8 header + 16 value
    }

    func testByteString1ExtraBytePadsToNext8() {
        let data = Data(repeating: 0xAB, count: 17)
        let encoded = encodeByteString(tag: 0x420043, value: data)
        XCTAssertEqual(encoded.count, 32) // 8 header + 24 padded
    }

    func testEmptyByteString() throws {
        let encoded = encodeByteString(tag: 0x420043, value: Data())
        XCTAssertEqual(encoded.count, 8)
        let decoded = try decodeTTLV(encoded)
        if case .byteString(let v) = decoded.value {
            XCTAssertEqual(v.count, 0)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    func testAES256KeyMaterialRoundTrip() throws {
        let key = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ])
        let encoded = encodeByteString(tag: 0x420043, value: key)
        XCTAssertEqual(encoded.count, 40) // 8 header + 32 value (exact alignment)
        let decoded = try decodeTTLV(encoded)
        if case .byteString(let v) = decoded.value {
            XCTAssertEqual(v, key)
        } else {
            XCTFail("Expected byte string value")
        }
    }

    // MARK: - Structures and tree navigation

    func testEncodeDecodeStructure() throws {
        let encoded = encodeStructure(tag: 0x420069, children: [
            encodeInteger(tag: 0x42006A, value: 1),
            encodeInteger(tag: 0x42006B, value: 4),
        ])
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.tag, 0x420069)
        XCTAssertEqual(decoded.type, TtlvType.structure.rawValue)
        if case .structure(let children) = decoded.value {
            XCTAssertEqual(children.count, 2)
            if case .integer(let v0) = children[0].value { XCTAssertEqual(v0, 1) }
            if case .integer(let v1) = children[1].value { XCTAssertEqual(v1, 4) }
        } else {
            XCTFail("Expected structure value")
        }
    }

    func testEmptyStructure() throws {
        let encoded = encodeStructure(tag: 0x420069, children: [])
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.type, TtlvType.structure.rawValue)
        if case .structure(let children) = decoded.value {
            XCTAssertEqual(children.count, 0)
        } else {
            XCTFail("Expected structure value")
        }
    }

    func testStructureWithMixedTypes() throws {
        let encoded = encodeStructure(tag: 0x420069, children: [
            encodeInteger(tag: 0x42006A, value: 42),
            encodeTextString(tag: 0x420055, value: "hello"),
            encodeBoolean(tag: 0x420008, value: true),
            encodeByteString(tag: 0x420043, value: Data([0xCA, 0xFE])),
            encodeEnum(tag: 0x42005C, value: 0x0A),
        ])
        let decoded = try decodeTTLV(encoded)
        if case .structure(let children) = decoded.value {
            XCTAssertEqual(children.count, 5)
            if case .integer(let v) = children[0].value { XCTAssertEqual(v, 42) }
            if case .textString(let v) = children[1].value { XCTAssertEqual(v, "hello") }
            if case .boolean(let v) = children[2].value { XCTAssertTrue(v) }
            if case .byteString(let v) = children[3].value { XCTAssertEqual(v, Data([0xCA, 0xFE])) }
            if case .enumeration(let v) = children[4].value { XCTAssertEqual(v, 0x0A) }
        } else {
            XCTFail("Expected structure value")
        }
    }

    func testFindChild() throws {
        let encoded = encodeStructure(tag: 0x420069, children: [
            encodeInteger(tag: 0x42006A, value: 1),
            encodeInteger(tag: 0x42006B, value: 4),
        ])
        let decoded = try decodeTTLV(encoded)
        let child = findChild(decoded, tag: 0x42006B)
        XCTAssertNotNil(child)
        if case .integer(let v) = child!.value {
            XCTAssertEqual(v, 4)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testFindChildReturnsNilForMissingTag() throws {
        let encoded = encodeStructure(tag: 0x420069, children: [
            encodeInteger(tag: 0x42006A, value: 1),
        ])
        let decoded = try decodeTTLV(encoded)
        XCTAssertNil(findChild(decoded, tag: 0x42FFFF))
    }

    func testFindChildReturnsNilForNonStructure() throws {
        let encoded = encodeInteger(tag: 0x42006A, value: 1)
        let decoded = try decodeTTLV(encoded)
        XCTAssertNil(findChild(decoded, tag: 0x42006A))
    }

    func testFindChildrenReturnsAllMatching() throws {
        let encoded = encodeStructure(tag: 0x420069, children: [
            encodeTextString(tag: 0x420094, value: "id-1"),
            encodeTextString(tag: 0x420094, value: "id-2"),
            encodeTextString(tag: 0x420094, value: "id-3"),
            encodeInteger(tag: 0x42006A, value: 99),
        ])
        let decoded = try decodeTTLV(encoded)
        let ids = findChildren(decoded, tag: 0x420094)
        XCTAssertEqual(ids.count, 3)
        if case .textString(let v0) = ids[0].value { XCTAssertEqual(v0, "id-1") }
        if case .textString(let v1) = ids[1].value { XCTAssertEqual(v1, "id-2") }
        if case .textString(let v2) = ids[2].value { XCTAssertEqual(v2, "id-3") }
    }

    func testFindChildrenReturnsEmptyForNonStructure() throws {
        let encoded = encodeInteger(tag: 0x42006A, value: 1)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(findChildren(decoded, tag: 0x42006A).count, 0)
    }

    func testNestedStructures() throws {
        let encoded = encodeStructure(tag: 0x420078, children: [
            encodeStructure(tag: 0x420077, children: [
                encodeStructure(tag: 0x420069, children: [
                    encodeInteger(tag: 0x42006A, value: 1),
                    encodeInteger(tag: 0x42006B, value: 4),
                ]),
                encodeInteger(tag: 0x42000D, value: 1),
            ]),
        ])
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.tag, 0x420078)
        let header = findChild(decoded, tag: 0x420077)
        XCTAssertNotNil(header)
        let version = findChild(header!, tag: 0x420069)
        XCTAssertNotNil(version)
        let major = findChild(version!, tag: 0x42006A)
        XCTAssertNotNil(major)
        if case .integer(let v) = major!.value {
            XCTAssertEqual(v, 1)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testThreeLevelNestedStructure() throws {
        let encoded = encodeStructure(tag: 0x420001, children: [
            encodeStructure(tag: 0x420002, children: [
                encodeStructure(tag: 0x420003, children: [
                    encodeTextString(tag: 0x420055, value: "deep"),
                ]),
            ]),
        ])
        let decoded = try decodeTTLV(encoded)
        let lvl1 = findChild(decoded, tag: 0x420002)
        XCTAssertNotNil(lvl1)
        let lvl2 = findChild(lvl1!, tag: 0x420003)
        XCTAssertNotNil(lvl2)
        let leaf = findChild(lvl2!, tag: 0x420055)
        XCTAssertNotNil(leaf)
        if case .textString(let v) = leaf!.value {
            XCTAssertEqual(v, "deep")
        } else {
            XCTFail("Expected text string value")
        }
    }

    // MARK: - Wire format verification

    func testTagEncoded3BytesBigEndian() throws {
        let encoded = encodeInteger(tag: 0x420069, value: 0)
        XCTAssertEqual(encoded[0], 0x42)
        XCTAssertEqual(encoded[1], 0x00)
        XCTAssertEqual(encoded[2], 0x69)
    }

    func testTypeByteCorrectForEachType() {
        XCTAssertEqual(encodeInteger(tag: 0x420001, value: 0)[3], TtlvType.integer.rawValue)
        XCTAssertEqual(encodeLongInteger(tag: 0x420001, value: 0)[3], TtlvType.longInteger.rawValue)
        XCTAssertEqual(encodeEnum(tag: 0x420001, value: 0)[3], TtlvType.enumeration.rawValue)
        XCTAssertEqual(encodeBoolean(tag: 0x420001, value: true)[3], TtlvType.boolean.rawValue)
        XCTAssertEqual(encodeTextString(tag: 0x420001, value: "x")[3], TtlvType.textString.rawValue)
        XCTAssertEqual(encodeByteString(tag: 0x420001, value: Data([1]))[3], TtlvType.byteString.rawValue)
        XCTAssertEqual(encodeStructure(tag: 0x420001, children: [])[3], TtlvType.structure.rawValue)
        XCTAssertEqual(encodeDateTime(tag: 0x420001, value: 0)[3], TtlvType.dateTime.rawValue)
    }

    func testLengthField4BytesBigEndianAtOffset4() {
        let encoded = encodeTextString(tag: 0x420055, value: "AB") // 2 bytes
        XCTAssertEqual(readLengthField(encoded), 2)
    }

    func testPaddingBytesAreZeroFilled() {
        let encoded = encodeTextString(tag: 0x420055, value: "AB") // 2 bytes -> padded to 8
        // Value starts at offset 8, length 2, padding at bytes 10-15
        for i in 10..<16 {
            XCTAssertEqual(encoded[i], 0, "padding byte at \(i) should be 0")
        }
    }

    // MARK: - Error handling

    func testThrowsOnBufferTooShortForHeader() {
        XCTAssertThrowsError(try decodeTTLV(Data(count: 4))) { error in
            XCTAssertTrue(error is TtlvError)
        }
    }

    func testThrowsOnEmptyBuffer() {
        XCTAssertThrowsError(try decodeTTLV(Data())) { error in
            XCTAssertTrue(error is TtlvError)
        }
    }

    // MARK: - Unicode and special strings

    func testUTF8MultiByteCharacters() throws {
        let encoded = encodeTextString(tag: 0x420055, value: "caf\u{00E9}")
        let decoded = try decodeTTLV(encoded)
        if case .textString(let v) = decoded.value {
            XCTAssertEqual(v, "caf\u{00E9}")
        } else {
            XCTFail("Expected text string value")
        }
    }

    func testEmojiInTextString() throws {
        let encoded = encodeTextString(tag: 0x420055, value: "key-\u{1F511}")
        let decoded = try decodeTTLV(encoded)
        if case .textString(let v) = decoded.value {
            XCTAssertEqual(v, "key-\u{1F511}")
        } else {
            XCTFail("Expected text string value")
        }
    }

    func testLongTextStringCrossingMultiple8ByteBoundaries() throws {
        let longStr = String(repeating: "a", count: 200) // 200 bytes
        let encoded = encodeTextString(tag: 0x420055, value: longStr)
        let decoded = try decodeTTLV(encoded)
        if case .textString(let v) = decoded.value {
            XCTAssertEqual(v, longStr)
        } else {
            XCTFail("Expected text string value")
        }
    }

    // MARK: - Security hardening tests

    func testRejectsDeclaredLengthExceedingBuffer() {
        // Header claiming 1000 bytes of value, but only 10 bytes provided
        var buf = Data(count: 18) // 8 header + 10 body
        buf[0] = 0x42; buf[1] = 0x00; buf[2] = 0x01 // tag = 0x420001
        buf[3] = 0x07 // type = TextString
        buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x03; buf[7] = 0xE8 // length = 1000
        XCTAssertThrowsError(try decodeTTLV(buf)) { error in
            XCTAssertTrue(error is TtlvError)
        }
    }

    func testAcceptsDeclaredLengthThatExactlyFitsBuffer() throws {
        let encoded = encodeInteger(tag: 0x420001, value: 42)
        let decoded = try decodeTTLV(encoded)
        if case .integer(let v) = decoded.value {
            XCTAssertEqual(v, 42)
        } else {
            XCTFail("Expected integer value")
        }
    }

    func testRejectsZeroLengthBuffer() {
        XCTAssertThrowsError(try decodeTTLV(Data())) { error in
            XCTAssertTrue(error is TtlvError)
        }
    }

    func testRejectsStructuresNestedDeeperThan32Levels() {
        // Build 33 levels of nesting
        var inner = encodeInteger(tag: 0x420001, value: 42)
        for _ in 0..<33 {
            inner = encodeStructure(tag: 0x420001, children: [inner])
        }
        XCTAssertThrowsError(try decodeTTLV(Data(inner))) { error in
            if let ttlvError = error as? TtlvError {
                if case .maxDepthExceeded = ttlvError {
                    // Expected
                } else {
                    XCTFail("Expected maxDepthExceeded error")
                }
            } else {
                XCTFail("Expected TtlvError")
            }
        }
    }

    func testAcceptsStructuresNestedExactly32LevelsDeep() throws {
        // Build 31 wrapping levels (root is depth 0, innermost is depth 31)
        var inner = encodeInteger(tag: 0x420001, value: 42)
        for _ in 0..<31 {
            inner = encodeStructure(tag: 0x420001, children: [inner])
        }
        let decoded = try decodeTTLV(Data(inner))
        XCTAssertEqual(decoded.type, TtlvType.structure.rawValue)
    }

    func testRejectsTruncatedHeader() {
        let buf = Data([0x42, 0x00, 0x01, 0x02])
        XCTAssertThrowsError(try decodeTTLV(buf)) { error in
            XCTAssertTrue(error is TtlvError)
        }
    }

    func testHandlesIntegerWithWrongLengthSafely() {
        // Header: tag=0x420001, type=Integer(0x02), length=3 (should be 4)
        var buf = Data(count: 16)
        buf[0] = 0x42; buf[1] = 0x00; buf[2] = 0x01
        buf[3] = 0x02 // type = Integer
        buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x03 // length = 3
        // Should either throw or handle safely — must not crash
        do {
            _ = try decodeTTLV(buf)
        } catch {
            // Any error is acceptable
        }
        // If we get here, the decoder handled it safely
        XCTAssertTrue(true, "decoder did not crash on malformed integer length")
    }

    // MARK: - Helper

    private func readLengthField(_ data: Data) -> UInt32 {
        return (UInt32(data[4]) << 24) |
               (UInt32(data[5]) << 16) |
               (UInt32(data[6]) << 8) |
               UInt32(data[7])
    }
}
