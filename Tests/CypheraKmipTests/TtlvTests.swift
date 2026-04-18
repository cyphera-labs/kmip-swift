//
// TtlvTests.swift
// CypheraKmipTests
//

import XCTest
@testable import CypheraKmip

final class TtlvTests: XCTestCase {
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

    func testEncodeDecodeBoolean() throws {
        let encoded = encodeBoolean(tag: 0x420008, value: true)
        let decoded = try decodeTTLV(encoded)
        XCTAssertEqual(decoded.type, TtlvType.boolean.rawValue)
        if case .boolean(let v) = decoded.value {
            XCTAssertTrue(v)
        } else {
            XCTFail("Expected boolean value")
        }
    }

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

    func testTextStringPadding() {
        // "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
        let encoded = encodeTextString(tag: 0x420055, value: "hello")
        XCTAssertEqual(encoded.count, 16) // 8 header + 8 padded value
    }

    func testEmptyTextString() throws {
        let encoded = encodeTextString(tag: 0x420055, value: "")
        let decoded = try decodeTTLV(encoded)
        if case .textString(let v) = decoded.value {
            XCTAssertEqual(v, "")
        } else {
            XCTFail("Expected text string value")
        }
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
}
