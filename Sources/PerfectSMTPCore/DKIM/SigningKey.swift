//
//  SigningKey.swift
//  PerfectSMTPCore
//
//  See Documentation/swift6-nio-rewrite-plan.md §4.6.
//

import Crypto
import Foundation
import _CryptoExtras

/// One DKIM signing key. `DKIMSigner.keys` takes one (single-algorithm
/// signing) or two -- one `.rsa`, one `.ed25519` -- for dual RSA+Ed25519
/// signing.
///
/// Sendability: both `_RSA.Signing.PrivateKey` and
/// `Curve25519.Signing.PrivateKey` are genuinely `Sendable` (not
/// `@unchecked`) in the pinned swift-crypto 4.5.1 -- verified directly
/// against the resolved package source, not assumed (see DKIMSigner.swift's
/// header comment for the specifics). `SigningKey` itself therefore needs
/// no `@unchecked Sendable` escape hatch.
public enum SigningKey: Sendable {
    case rsa(_RSA.Signing.PrivateKey)
    case ed25519(Curve25519.Signing.PrivateKey)

    /// Parses a PEM-encoded RSA private key. Uses swift-crypto's
    /// 2048-bit-minimum `pemRepresentation:` initializer -- never
    /// `unsafePEMRepresentation:`, which permits keys down to 1024 bits --
    /// so this is the primary place RFC 6376 §3.3.3's RSA-2048 minimum
    /// (plan §4.6) is enforced. `DKIMSigner.init` re-checks
    /// `keySizeInBits` defensively too, in case a caller constructs
    /// `.rsa(_:)` directly from a key parsed some other way (e.g. from raw
    /// DER via `unsafeDERRepresentation:`), bypassing this convenience.
    public static func rsa(pem: String) throws -> SigningKey {
        .rsa(try _RSA.Signing.PrivateKey(pemRepresentation: pem))
    }

    /// Constructs an Ed25519 key (RFC 8463) from its 32-byte raw
    /// representation.
    public static func ed25519(rawRepresentation: some ContiguousBytes) throws -> SigningKey {
        .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: rawRepresentation))
    }

    var algorithm: DKIMSigner.Algorithm {
        switch self {
        case .rsa: return .rsaSHA256
        case .ed25519: return .ed25519SHA256
        }
    }

    /// Signs `hashInput` per RFC 6376 §3.3.2 (RSA-SHA256) or RFC 8463 §3
    /// (Ed25519-SHA256): both algorithms compute a SHA-256 digest of the
    /// DKIM signing input first (RFC 6376 §3.7's `data-hash`); RSA then
    /// PKCS#1-v1.5-signs that digest directly, while Ed25519-SHA256 signs
    /// the 32-byte digest bytes as the PureEdDSA "message" (RFC 8463 §3:
    /// the SHA-256 pre-hash is DKIM's own framing, layered on top of, not
    /// replacing, whatever Ed25519 does internally -- Ed25519 separately
    /// does its own SHA-512-based internal hashing as part of the EdDSA
    /// algorithm itself, which is orthogonal to this pre-hash). Returns
    /// the base64-encoded signature for the `b=` tag.
    ///
    /// Note (see the DKIMSigner.swift header comment and the test suite's
    /// `RFC8463VectorTests` for the full explanation): swift-crypto's
    /// Ed25519 signing on Apple platforms passes through to Apple
    /// CryptoKit, which intentionally randomizes its EdDSA nonce as a
    /// side-channel defense -- meaning two calls to `sign` with identical
    /// `hashInput`/key produce *different*, but equally valid, signature
    /// bytes each time. This is still a fully RFC 8032/8463-conformant
    /// signature (any conformant verifier accepts it), just not a
    /// deterministic one, and is why this signer's RSA path (deterministic
    /// PKCS#1 v1.5) and Ed25519 path (verified, not byte-compared) are
    /// tested differently against the real RFC 8463 vector.
    func sign(_ hashInput: [UInt8]) throws -> String {
        let digest = SHA256.hash(data: Data(hashInput))
        switch self {
        case .rsa(let privateKey):
            // .insecurePKCS1v1_5 -- despite the name, this is exactly the
            // RFC 6376-mandated PKCS#1 v1.5 padding (plan §4.6), not a
            // downgrade. Substituting PSS here would produce a signature
            // no real-world DKIM verifier accepts.
            let signature = try privateKey.signature(for: digest, padding: .insecurePKCS1v1_5)
            return signature.rawRepresentation.base64EncodedString()
        case .ed25519(let privateKey):
            let signature = try privateKey.signature(for: Data(digest))
            return signature.base64EncodedString()
        }
    }
}
