//
//  DotStuffing.swift
//  PerfectSMTPCore
//
//  RFC 5321 §4.5.2 transparency: any line beginning with '.' has that dot
//  doubled before transmission, and the DATA phase is terminated by a
//  line consisting of a single '.' followed by CRLF. This is a
//  wire-transparency mechanism the receiver reverses before further
//  processing — it is applied to (and is orthogonal to) an already-signed
//  message; DKIM canonicalization operates on the logical message, dot-
//  stuffing on the wire form (plan §4.6).
//

public enum DotStuffing {
    /// Applies leading-dot doubling to every line of `message`, then
    /// appends the terminal `.\r\n` sequence that signals end-of-DATA.
    /// Ensures the transformed content ends in CRLF before the terminator
    /// is appended, even if `message` itself did not end in CRLF.
    public static func encode(_ message: [UInt8]) -> [UInt8] {
        let dot: UInt8 = 0x2E
        let cr: UInt8 = 0x0D
        let lf: UInt8 = 0x0A

        var output = [UInt8]()
        output.reserveCapacity(message.count + 8)

        var atLineStart = true
        for byte in message {
            if atLineStart && byte == dot {
                output.append(dot)
            }
            output.append(byte)
            atLineStart = (byte == lf)
        }

        if !(output.count >= 2 && output[output.count - 2] == cr && output[output.count - 1] == lf) {
            output.append(cr)
            output.append(lf)
        }
        output.append(dot)
        output.append(cr)
        output.append(lf)
        return output
    }
}
