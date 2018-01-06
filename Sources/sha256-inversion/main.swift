import Foundation
import Utility
import Basic

var block1 = BlockHeader(version: 0x01000000,
                         prevHash: [0x81, 0xcd, 0x02, 0xab, 0x7e, 0x56, 0x9e, 0x8b, 0xcd, 0x93, 0x17, 0xe2, 0xfe, 0x99, 0xf2, 0xde, 0x44, 0xd4, 0x9a, 0xb2, 0xb8, 0x85, 0x1b, 0xa4, 0xa3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                         merkleRoot: [0xe3, 0x20, 0xb6, 0xc2, 0xff, 0xfc, 0x8d, 0x75, 0x04, 0x23, 0xdb, 0x8b,0x1e, 0xb9, 0x42, 0xae, 0x71, 0x0e, 0x95, 0x1e, 0xd7, 0x97, 0xf7, 0xaf, 0xfc, 0x88, 0x92, 0xb0, 0xf1, 0xfc, 0x12, 0x2b],
                         timestamp: 0xc7f5d74d,
                         bits: 0xf2b9441a,
                         nonce: 0x42a14695)
//
let setup = benchmark {
    _ = BTC_SHA256(block1.bytes())
}

let hash1 = BTC_SHA256(block1.bytes())
//
let hashrate = 1/benchmark(iter: 100000) { i in
    _ = hash1.hashWithNonce(nonce: i)
}

print(hash1.hashWithNonce(nonce: 0x42a14695)?.hex() ?? "incorrect nonce")
print("\(setup) setup time.")
print("\(hashrate) hashes/sec")

var block3 = BlockHeader(version: 0x02000000, prevHash: "b6ff0b1b1680a2862a30ca44d346d9e8910d334beb48ca0c0000000000000000", merkleRoot: "9d10aa52ee949386ca9385695f04ede270dda20810decd12bc9b048aaab31471", timestamp: 0x24d95a54, bits: 0x30c31b18, nonce: 0xfe9f0864)
let hash3 = BTC_SHA256(block3.bytes())
print(hash3.hashWithNonce(nonce: 0xfe9f0864)?.hex() ?? "incorrect nonce")

var block4 = BlockHeader(version: 0x00000020,
                         prevHash: "218c1510d19462136dd26ef4c50d3c84ccdfdc3a000bd3000000000000000000",
                       merkleRoot: "3e1a4f1907fcd24bec0db00a7b7a50f88a5397a59d289d6a650218fb22c2f8dd",
                       timestamp: 0x329a5558,
                       bits: 0x858b0318,
                       nonce: 0x3c3e0de9)
let hash4 = BTC_SHA256(block4.bytes())
print(hash4.hashWithNonce(nonce: /*0x3c3e0de9*/ 0x3c3e0fe9)?.hex() ?? "incorrect nonce")

