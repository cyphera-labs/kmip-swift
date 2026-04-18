//
// TagTests.swift
// CypheraKmipTests
//
// Tests verifying KMIP 1.4 spec constants: tags, operations,
// object types, algorithms, key format types, usage masks.
//

import XCTest
@testable import CypheraKmip

final class TagTests: XCTestCase {

    // MARK: - ObjectType (KMIP 1.4 Section 9.1.3.2.3)

    func testObjectTypeCertificate()  { XCTAssertEqual(KmipObjectType.Certificate,  0x00000001) }
    func testObjectTypeSymmetricKey() { XCTAssertEqual(KmipObjectType.SymmetricKey, 0x00000002) }
    func testObjectTypePublicKey()    { XCTAssertEqual(KmipObjectType.PublicKey,    0x00000003) }
    func testObjectTypePrivateKey()   { XCTAssertEqual(KmipObjectType.PrivateKey,   0x00000004) }
    func testObjectTypeSplitKey()     { XCTAssertEqual(KmipObjectType.SplitKey,     0x00000005) }
    func testObjectTypeTemplate()     { XCTAssertEqual(KmipObjectType.Template,     0x00000006) }
    func testObjectTypeSecretData()   { XCTAssertEqual(KmipObjectType.SecretData,   0x00000007) }
    func testObjectTypeOpaqueData()   { XCTAssertEqual(KmipObjectType.OpaqueData,   0x00000008) }

    func testObjectTypeNoDuplicates() {
        let values: [UInt32] = [
            KmipObjectType.Certificate, KmipObjectType.SymmetricKey,
            KmipObjectType.PublicKey, KmipObjectType.PrivateKey,
            KmipObjectType.SplitKey, KmipObjectType.Template,
            KmipObjectType.SecretData, KmipObjectType.OpaqueData,
        ]
        XCTAssertEqual(Set(values).count, values.count)
    }

    // MARK: - Operations (KMIP 1.4 Section 9.1.3.2.2)

    func testOperationCreate()   { XCTAssertEqual(KmipOperation.Create,   0x00000001) }
    func testOperationLocate()   { XCTAssertEqual(KmipOperation.Locate,   0x00000008) }
    func testOperationGet()      { XCTAssertEqual(KmipOperation.Get,      0x0000000A) }
    func testOperationActivate() { XCTAssertEqual(KmipOperation.Activate, 0x00000012) }
    func testOperationDestroy()  { XCTAssertEqual(KmipOperation.Destroy,  0x00000014) }
    func testOperationCheck()    { XCTAssertEqual(KmipOperation.Check,    0x00000009) }

    func testOperationNoDuplicates() {
        let values: [UInt32] = [
            KmipOperation.Create, KmipOperation.Locate, KmipOperation.Get,
            KmipOperation.Activate, KmipOperation.Destroy, KmipOperation.Check,
        ]
        XCTAssertEqual(Set(values).count, values.count)
    }

    // MARK: - ResultStatus

    func testResultStatusSuccess()          { XCTAssertEqual(KmipResultStatus.Success,          0x00000000) }
    func testResultStatusOperationFailed()  { XCTAssertEqual(KmipResultStatus.OperationFailed,  0x00000001) }
    func testResultStatusOperationPending() { XCTAssertEqual(KmipResultStatus.OperationPending, 0x00000002) }
    func testResultStatusOperationUndone()  { XCTAssertEqual(KmipResultStatus.OperationUndone,  0x00000003) }

    func testResultStatusNoDuplicates() {
        let values: [UInt32] = [
            KmipResultStatus.Success, KmipResultStatus.OperationFailed,
            KmipResultStatus.OperationPending, KmipResultStatus.OperationUndone,
        ]
        XCTAssertEqual(Set(values).count, values.count)
    }

    // MARK: - Algorithms (KMIP 1.4 Section 9.1.3.2.13)

    func testAlgorithmDES()        { XCTAssertEqual(KmipAlgorithm.DES,        0x00000001) }
    func testAlgorithmTripleDES()  { XCTAssertEqual(KmipAlgorithm.TripleDES,  0x00000002) }
    func testAlgorithmAES()        { XCTAssertEqual(KmipAlgorithm.AES,        0x00000003) }
    func testAlgorithmRSA()        { XCTAssertEqual(KmipAlgorithm.RSA,        0x00000004) }
    func testAlgorithmDSA()        { XCTAssertEqual(KmipAlgorithm.DSA,        0x00000005) }
    func testAlgorithmECDSA()      { XCTAssertEqual(KmipAlgorithm.ECDSA,      0x00000006) }
    func testAlgorithmHMACSHA1()   { XCTAssertEqual(KmipAlgorithm.HMACSHA1,   0x00000007) }
    func testAlgorithmHMACSHA256() { XCTAssertEqual(KmipAlgorithm.HMACSHA256, 0x00000008) }
    func testAlgorithmHMACSHA384() { XCTAssertEqual(KmipAlgorithm.HMACSHA384, 0x00000009) }
    func testAlgorithmHMACSHA512() { XCTAssertEqual(KmipAlgorithm.HMACSHA512, 0x0000000A) }

    func testAlgorithmNoDuplicates() {
        let values: [UInt32] = [
            KmipAlgorithm.DES, KmipAlgorithm.TripleDES, KmipAlgorithm.AES,
            KmipAlgorithm.RSA, KmipAlgorithm.DSA, KmipAlgorithm.ECDSA,
            KmipAlgorithm.HMACSHA1, KmipAlgorithm.HMACSHA256,
            KmipAlgorithm.HMACSHA384, KmipAlgorithm.HMACSHA512,
        ]
        XCTAssertEqual(Set(values).count, values.count)
    }

    // MARK: - KeyFormatType

    func testKeyFormatTypeRaw()                  { XCTAssertEqual(KmipKeyFormatType.Raw,                  0x00000001) }
    func testKeyFormatTypeOpaque()               { XCTAssertEqual(KmipKeyFormatType.Opaque,               0x00000002) }
    func testKeyFormatTypePKCS1()                { XCTAssertEqual(KmipKeyFormatType.PKCS1,                0x00000003) }
    func testKeyFormatTypePKCS8()                { XCTAssertEqual(KmipKeyFormatType.PKCS8,                0x00000004) }
    func testKeyFormatTypeX509()                 { XCTAssertEqual(KmipKeyFormatType.X509,                 0x00000005) }
    func testKeyFormatTypeECPrivateKey()         { XCTAssertEqual(KmipKeyFormatType.ECPrivateKey,         0x00000006) }
    func testKeyFormatTypeTransparentSymmetric() { XCTAssertEqual(KmipKeyFormatType.TransparentSymmetric, 0x00000007) }

    func testKeyFormatTypeNoDuplicates() {
        let values: [UInt32] = [
            KmipKeyFormatType.Raw, KmipKeyFormatType.Opaque,
            KmipKeyFormatType.PKCS1, KmipKeyFormatType.PKCS8,
            KmipKeyFormatType.X509, KmipKeyFormatType.ECPrivateKey,
            KmipKeyFormatType.TransparentSymmetric,
        ]
        XCTAssertEqual(Set(values).count, values.count)
    }

    // MARK: - NameType

    func testNameTypeUninterpretedTextString() { XCTAssertEqual(KmipNameType.UninterpretedTextString, 0x00000001) }
    func testNameTypeURI()                     { XCTAssertEqual(KmipNameType.URI,                     0x00000002) }

    // MARK: - UsageMask (bitmask)

    func testUsageMaskSign()         { XCTAssertEqual(KmipUsageMask.Sign,         0x00000001) }
    func testUsageMaskVerify()       { XCTAssertEqual(KmipUsageMask.Verify,       0x00000002) }
    func testUsageMaskEncrypt()      { XCTAssertEqual(KmipUsageMask.Encrypt,      0x00000004) }
    func testUsageMaskDecrypt()      { XCTAssertEqual(KmipUsageMask.Decrypt,      0x00000008) }
    func testUsageMaskWrapKey()      { XCTAssertEqual(KmipUsageMask.WrapKey,      0x00000010) }
    func testUsageMaskUnwrapKey()    { XCTAssertEqual(KmipUsageMask.UnwrapKey,    0x00000020) }
    func testUsageMaskExport()       { XCTAssertEqual(KmipUsageMask.Export,       0x00000040) }
    func testUsageMaskDeriveKey()    { XCTAssertEqual(KmipUsageMask.DeriveKey,    0x00000100) }
    func testUsageMaskKeyAgreement() { XCTAssertEqual(KmipUsageMask.KeyAgreement, 0x00000800) }

    func testUsageMaskEncryptDecryptCombines() {
        XCTAssertEqual(KmipUsageMask.Encrypt | KmipUsageMask.Decrypt, 0x0000000C)
    }

    func testUsageMaskAllDistinctBits() {
        let values: [UInt32] = [
            KmipUsageMask.Sign, KmipUsageMask.Verify,
            KmipUsageMask.Encrypt, KmipUsageMask.Decrypt,
            KmipUsageMask.WrapKey, KmipUsageMask.UnwrapKey,
            KmipUsageMask.Export, KmipUsageMask.DeriveKey,
            KmipUsageMask.KeyAgreement,
        ]
        var combined: UInt32 = 0
        for v in values {
            XCTAssertEqual(combined & v, 0, "value 0x\(String(v, radix: 16)) overlaps with previous values")
            combined |= v
        }
    }

    // MARK: - Tag values in KMIP range

    func testAllTagValuesInKmipRange() {
        let allTags: [(String, UInt32)] = [
            ("RequestMessage", Tag.RequestMessage),
            ("ResponseMessage", Tag.ResponseMessage),
            ("RequestHeader", Tag.RequestHeader),
            ("ResponseHeader", Tag.ResponseHeader),
            ("ProtocolVersion", Tag.ProtocolVersion),
            ("ProtocolVersionMajor", Tag.ProtocolVersionMajor),
            ("ProtocolVersionMinor", Tag.ProtocolVersionMinor),
            ("BatchCount", Tag.BatchCount),
            ("BatchItem", Tag.BatchItem),
            ("Operation", Tag.Operation),
            ("RequestPayload", Tag.RequestPayload),
            ("ResponsePayload", Tag.ResponsePayload),
            ("ResultStatus", Tag.ResultStatus),
            ("ResultReason", Tag.ResultReason),
            ("ResultMessage", Tag.ResultMessage),
            ("UniqueIdentifier", Tag.UniqueIdentifier),
            ("ObjectType", Tag.ObjectType),
            ("Name", Tag.Name),
            ("NameValue", Tag.NameValue),
            ("NameType", Tag.NameType),
            ("Attribute", Tag.Attribute),
            ("AttributeName", Tag.AttributeName),
            ("AttributeValue", Tag.AttributeValue),
            ("SymmetricKey", Tag.SymmetricKey),
            ("KeyBlock", Tag.KeyBlock),
            ("KeyFormatType", Tag.KeyFormatType),
            ("KeyValue", Tag.KeyValue),
            ("KeyMaterial", Tag.KeyMaterial),
            ("CryptographicAlgorithm", Tag.CryptographicAlgorithm),
            ("CryptographicLength", Tag.CryptographicLength),
            ("CryptographicUsageMask", Tag.CryptographicUsageMask),
            ("TemplateAttribute", Tag.TemplateAttribute),
        ]
        for (name, value) in allTags {
            XCTAssertTrue(
                value >= 0x420000 && value <= 0x42FFFF,
                "Tag.\(name) = 0x\(String(value, radix: 16)) is outside 0x42XXXX range"
            )
        }
    }

    func testNoDuplicateTagValues() {
        let values: [UInt32] = [
            Tag.RequestMessage, Tag.ResponseMessage,
            Tag.RequestHeader, Tag.ResponseHeader,
            Tag.ProtocolVersion, Tag.ProtocolVersionMajor, Tag.ProtocolVersionMinor,
            Tag.BatchCount, Tag.BatchItem, Tag.Operation,
            Tag.RequestPayload, Tag.ResponsePayload,
            Tag.ResultStatus, Tag.ResultReason, Tag.ResultMessage,
            Tag.UniqueIdentifier, Tag.ObjectType,
            Tag.Name, Tag.NameValue, Tag.NameType,
            Tag.Attribute, Tag.AttributeName, Tag.AttributeValue,
            Tag.SymmetricKey, Tag.KeyBlock, Tag.KeyFormatType,
            Tag.KeyValue, Tag.KeyMaterial,
            Tag.CryptographicAlgorithm, Tag.CryptographicLength,
            Tag.CryptographicUsageMask, Tag.TemplateAttribute,
        ]
        XCTAssertEqual(Set(values).count, values.count)
    }
}
