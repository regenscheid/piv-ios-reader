import Foundation

/// Parsed CHUID (Card Holder Unique Identifier) data object.
struct PIVChuid: PIVDataObject {
    let rawData: Data
    let tag: UInt32
    let name: String
    let fascn: FASCN?
    let guid: Data?              // 16 bytes
    let expirationDate: String?  // YYYYMMDD ASCII
    let issuerSignature: Data?
    let errorDetectionCode: Data?

    /// GUID formatted as RFC 4122 UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
    var guidUUID: String? {
        guard let guid = guid, guid.count == 16 else { return nil }
        let h = guid.map { String(format: "%02x", $0) }.joined()
        let i = { (start: Int, len: Int) -> String in
            let s = h.index(h.startIndex, offsetBy: start)
            let e = h.index(s, offsetBy: len)
            return String(h[s..<e])
        }
        return "\(i(0,8))-\(i(8,4))-\(i(12,4))-\(i(16,4))-\(i(20,12))"
    }
}
