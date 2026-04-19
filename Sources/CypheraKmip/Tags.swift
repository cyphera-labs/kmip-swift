//
// Tags.swift
// CypheraKmip
//
// KMIP 1.4 tag, type, and enum constants.
// Full 27-operation support matching the Go reference.
//
// Reference: OASIS KMIP Specification v1.4
// https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
//

import Foundation

public enum Tag {
    // Message structure
    public static let RequestMessage:       UInt32 = 0x420078
    public static let ResponseMessage:      UInt32 = 0x42007B
    public static let RequestHeader:        UInt32 = 0x420077
    public static let ResponseHeader:       UInt32 = 0x42007A
    public static let ProtocolVersion:      UInt32 = 0x420069
    public static let ProtocolVersionMajor: UInt32 = 0x42006A
    public static let ProtocolVersionMinor: UInt32 = 0x42006B
    public static let BatchCount:           UInt32 = 0x42000D
    public static let BatchItem:            UInt32 = 0x42000F
    public static let Operation:            UInt32 = 0x42005C
    public static let RequestPayload:       UInt32 = 0x420079
    public static let ResponsePayload:      UInt32 = 0x42007C
    public static let ResultStatus:         UInt32 = 0x42007F
    public static let ResultReason:         UInt32 = 0x420080
    public static let ResultMessage:        UInt32 = 0x420081

    // Object identification
    public static let UniqueIdentifier:     UInt32 = 0x420094
    public static let ObjectType:           UInt32 = 0x420057

    // Naming
    public static let Name:                 UInt32 = 0x420053
    public static let NameValue:            UInt32 = 0x420055
    public static let NameType:             UInt32 = 0x420054

    // Attributes (KMIP 1.x style)
    public static let Attribute:            UInt32 = 0x420008
    public static let AttributeName:        UInt32 = 0x42000A
    public static let AttributeValue:       UInt32 = 0x42000B

    // Key structure
    public static let SymmetricKey:         UInt32 = 0x42008F
    public static let KeyBlock:             UInt32 = 0x420040
    public static let KeyFormatType:        UInt32 = 0x420042
    public static let KeyValue:             UInt32 = 0x420045
    public static let KeyMaterial:          UInt32 = 0x420043

    // Crypto attributes
    public static let CryptographicAlgorithm: UInt32 = 0x420028
    public static let CryptographicLength:    UInt32 = 0x42002A
    public static let CryptographicUsageMask: UInt32 = 0x42002C

    // Template
    public static let TemplateAttribute:    UInt32 = 0x420091

    // Key pair
    public static let PrivateKeyUniqueIdentifier: UInt32 = 0x420066
    public static let PublicKeyUniqueIdentifier:  UInt32 = 0x42006F
    public static let PublicKey:                  UInt32 = 0x42004E
    public static let PrivateKey:                 UInt32 = 0x42004D

    // Certificate
    public static let Certificate:      UInt32 = 0x420021
    public static let CertificateType:  UInt32 = 0x42001D
    public static let CertificateValue: UInt32 = 0x42001E

    // Crypto operations
    public static let Data:              UInt32 = 0x420033
    public static let IVCounterNonce:    UInt32 = 0x420047
    public static let SignatureData:     UInt32 = 0x42004F
    public static let MACData:           UInt32 = 0x420051
    public static let ValidityIndicator: UInt32 = 0x420098

    // Revocation
    public static let RevocationReason:     UInt32 = 0x420082
    public static let RevocationReasonCode: UInt32 = 0x420083

    // Query
    public static let QueryFunction: UInt32 = 0x420074

    // State
    public static let State: UInt32 = 0x42008D

    // Derivation
    public static let DerivationMethod:     UInt32 = 0x420031
    public static let DerivationParameters: UInt32 = 0x420032
    public static let DerivationData:       UInt32 = 0x420030

    // Lease
    public static let LeaseTime: UInt32 = 0x420049
}

public enum KmipOperation {
    public static let Create:           UInt32 = 0x00000001
    public static let CreateKeyPair:    UInt32 = 0x00000002
    public static let Register:         UInt32 = 0x00000003
    public static let ReKey:            UInt32 = 0x00000004
    public static let DeriveKey:        UInt32 = 0x00000005
    public static let Locate:           UInt32 = 0x00000008
    public static let Check:            UInt32 = 0x00000009
    public static let Get:              UInt32 = 0x0000000A
    public static let GetAttributes:    UInt32 = 0x0000000B
    public static let GetAttributeList: UInt32 = 0x0000000C
    public static let AddAttribute:     UInt32 = 0x0000000D
    public static let ModifyAttribute:  UInt32 = 0x0000000E
    public static let DeleteAttribute:  UInt32 = 0x0000000F
    public static let ObtainLease:      UInt32 = 0x00000010
    public static let Activate:         UInt32 = 0x00000012
    public static let Revoke:           UInt32 = 0x00000013
    public static let Destroy:          UInt32 = 0x00000014
    public static let Archive:          UInt32 = 0x00000015
    public static let Recover:          UInt32 = 0x00000016
    public static let Query:            UInt32 = 0x00000018
    public static let Poll:             UInt32 = 0x0000001A
    public static let DiscoverVersions: UInt32 = 0x0000001E
    public static let Encrypt:          UInt32 = 0x0000001F
    public static let Decrypt:          UInt32 = 0x00000020
    public static let Sign:             UInt32 = 0x00000021
    public static let SignatureVerify:  UInt32 = 0x00000022
    public static let MAC:              UInt32 = 0x00000023
}

public enum KmipObjectType {
    public static let Certificate:  UInt32 = 0x00000001
    public static let SymmetricKey: UInt32 = 0x00000002
    public static let PublicKey:    UInt32 = 0x00000003
    public static let PrivateKey:   UInt32 = 0x00000004
    public static let SplitKey:     UInt32 = 0x00000005
    public static let Template:     UInt32 = 0x00000006
    public static let SecretData:   UInt32 = 0x00000007
    public static let OpaqueData:   UInt32 = 0x00000008
}

public enum KmipResultStatus {
    public static let Success:          UInt32 = 0x00000000
    public static let OperationFailed:  UInt32 = 0x00000001
    public static let OperationPending: UInt32 = 0x00000002
    public static let OperationUndone:  UInt32 = 0x00000003
}

public enum KmipKeyFormatType {
    public static let Raw:                  UInt32 = 0x00000001
    public static let Opaque:               UInt32 = 0x00000002
    public static let PKCS1:                UInt32 = 0x00000003
    public static let PKCS8:                UInt32 = 0x00000004
    public static let X509:                 UInt32 = 0x00000005
    public static let ECPrivateKey:         UInt32 = 0x00000006
    public static let TransparentSymmetric: UInt32 = 0x00000007
}

public enum KmipAlgorithm {
    public static let DES:        UInt32 = 0x00000001
    public static let TripleDES:  UInt32 = 0x00000002
    public static let AES:        UInt32 = 0x00000003
    public static let RSA:        UInt32 = 0x00000004
    public static let DSA:        UInt32 = 0x00000005
    public static let ECDSA:      UInt32 = 0x00000006
    public static let HMACSHA1:   UInt32 = 0x00000007
    public static let HMACSHA256: UInt32 = 0x00000008
    public static let HMACSHA384: UInt32 = 0x00000009
    public static let HMACSHA512: UInt32 = 0x0000000A
}

public enum KmipNameType {
    public static let UninterpretedTextString: UInt32 = 0x00000001
    public static let URI:                     UInt32 = 0x00000002
}

public enum KmipUsageMask {
    public static let Sign:         UInt32 = 0x00000001
    public static let Verify:       UInt32 = 0x00000002
    public static let Encrypt:      UInt32 = 0x00000004
    public static let Decrypt:      UInt32 = 0x00000008
    public static let WrapKey:      UInt32 = 0x00000010
    public static let UnwrapKey:    UInt32 = 0x00000020
    public static let Export:       UInt32 = 0x00000040
    public static let DeriveKey:    UInt32 = 0x00000100
    public static let KeyAgreement: UInt32 = 0x00000800
}
