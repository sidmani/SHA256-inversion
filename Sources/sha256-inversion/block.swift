import Foundation

struct BlockHeader {
    let version: UInt32
    let prevHash: [UInt8]
    let merkleRoot: [UInt8]
    var timestamp: UInt32
    let bits: UInt32
    var nonce: UInt32

    init(version: UInt32, prevHash: [UInt8], merkleRoot: [UInt8], timestamp: UInt32, bits: UInt32, nonce: UInt32) {
        self.version = version
        self.prevHash = prevHash
        self.merkleRoot = merkleRoot
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
    }

    init(version: UInt32, prevHash: String, merkleRoot: String, timestamp: UInt32, bits: UInt32, nonce: UInt32) {
        self.version = version
        self.prevHash = prevHash.hexToBytes()
        self.merkleRoot = merkleRoot.hexToBytes()
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
    }

    func bytes() -> [UInt8] {
        return
            version.bytes_littleEndian() // 4 bytes
            + prevHash // 32 bytes
            + merkleRoot // 32 bytes
            + timestamp.bytes_littleEndian() // 4 bytes
            + bits.bytes_littleEndian() // 4 bytes
            + nonce.bytes_littleEndian() // 4 bytes
    }
}

extension UInt32 {
    func bytes_littleEndian() -> [UInt8] {
        return [
            UInt8((self >> 24) & 0xff), // little-endian
            UInt8((self >> 16) & 0xff),
            UInt8((self >> 08) & 0xff),
            UInt8((self >> 00) & 0xff)
        ]
    }
}
