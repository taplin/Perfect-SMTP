//
//  DKIMSigningInput.swift
//  PerfectSMTPCore
//
//  RFC 6376 §3.7's hash-step-2 (header hash) input construction, and
//  §5.4.2's bottom-up multiple-instance selection -- kept as a pure
//  function, independent of `DKIMSigner`'s own oversigning policy
//  (`DKIMSigner.effectiveHeaderNames`, in DKIMSigner.swift), so it can be
//  exercised directly against the real, published RFC 8463 Appendix A
//  vector with an explicit `h=` name list, rather than only indirectly
//  through DKIMSigner's own header-selection policy. This separation is
//  deliberate: it lets a test prove the core RFC algorithm (canonicalize,
//  select bottom-up, hash) is byte-exact against a real vector, and
//  separately prove the oversigning *policy* correctly protects against
//  header injection, without either test's correctness depending on the
//  other's design choices.
//

enum DKIMSigningInput {
    /// Builds the exact byte sequence passed to hash-alg for RFC 6376
    /// §3.7 hash step 2: the `h=`-selected headers (in the order and
    /// repeat-count `hNames` specifies), each canonicalized and CRLF-
    /// terminated, followed by the DKIM-Signature header itself
    /// (canonicalized, `b=` empty, no trailing CRLF).
    ///
    /// `hNames` may repeat a name (multiple-instance signing / oversigning,
    /// §5.4.2) and may name a header absent from `actualHeaders` entirely
    /// (§5.4: "Signers MAY claim to have signed header fields that do not
    /// exist" -- such an absent/"phantom" entry contributes nothing at all
    /// to the hash, per "the nonexisting header field MUST be treated as
    /// the null string (including the header field name, header field
    /// value, all punctuation, and the trailing CRLF)" -- it only affects
    /// the emitted `h=` tag text).
    ///
    /// Multiple-instance selection is bottom-up per §5.4.2: "MUST sign
    /// such header fields in order from the bottom of the header field
    /// block to the top." Each successive occurrence of the same name in
    /// `hNames` consumes the next-higher-up not-yet-consumed instance of
    /// that header.
    static func headerHashInput(
        actualHeaders: [(name: String, value: String)],
        hNames: [String],
        headerMode: DKIMSigner.Mode,
        dkimSignatureHeaderValue: String
    ) -> [UInt8] {
        var input: [UInt8] = []
        var consumedSoFar: [String: Int] = [:]

        for name in hNames {
            let lower = name.lowercased()
            let matchesTopToBottom = actualHeaders.filter { $0.name.lowercased() == lower }
            let bottomUp = Array(matchesTopToBottom.reversed())
            let nextIndex = consumedSoFar[lower, default: 0]
            consumedSoFar[lower, default: 0] += 1

            guard nextIndex < bottomUp.count else {
                continue // Phantom entry: null contribution, per §5.4.
            }
            let header = bottomUp[nextIndex]
            let canonicalized = DKIMCanonicalization.canonicalizeHeader(
                name: header.name, value: header.value, mode: headerMode
            )
            input.append(contentsOf: Array(canonicalized.utf8))
        }

        let dkimLine = DKIMCanonicalization.canonicalizeHeader(
            name: "DKIM-Signature", value: dkimSignatureHeaderValue, mode: headerMode
        )
        // "without a trailing CRLF" (§3.7 step 2) -- canonicalizeHeader
        // always appends one; stripped here rather than special-casing the
        // DKIM-Signature header inside canonicalizeHeader itself.
        //
        // Deliberately drops the trailing bytes at the UTF-8 level, not via
        // `String.removeLast(2)`: Swift's default grapheme-cluster
        // segmentation treats a trailing CR+LF as a *single* `Character`,
        // so `removeLast(2)` would remove that one CRLF "character" plus
        // one real content character beyond it -- silently truncating the
        // signing input by one byte too many.
        var dkimLineBytes = Array(dkimLine.utf8)
        dkimLineBytes.removeLast(2)
        input.append(contentsOf: dkimLineBytes)
        return input
    }
}
