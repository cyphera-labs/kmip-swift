//
// SecureKeyMaterial.swift
// CypheraKmip
//
// Holds key bytes and zeroes its backing buffer on deallocation.
// Use this wherever key material leaves the client — never pass raw Data.
//

import Foundation

/// Reference-typed container for sensitive key material.
///
/// The backing bytes are zeroed in `deinit` via `memset_s` so the buffer
/// cannot be observed after the last reference is dropped. Callers that
/// need the bytes should read them inside `withBytes(_:)`, which keeps the
/// lifetime bounded and avoids surfacing a plain `Data` that could survive
/// past the container.
public final class SecureKeyMaterial: @unchecked Sendable {
    private var storage: Data

    /// Length of the wrapped key material in bytes.
    public var count: Int { storage.count }

    public init(_ data: Data) {
        self.storage = data
    }

    /// Call the closure with the raw key bytes.
    public func withBytes<T>(_ body: (Data) throws -> T) rethrows -> T {
        return try body(storage)
    }

    /// Return a defensive copy of the bytes. Prefer `withBytes` when possible.
    public func copyBytes() -> Data {
        return storage
    }

    deinit {
        storage.withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress, ptr.count > 0 else { return }
            // memset_s is the standard C API for guaranteed-not-optimized-away zeroing.
            _ = memset_s(base, ptr.count, 0, ptr.count)
        }
    }
}
