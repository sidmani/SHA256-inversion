// This source file contains code from the Swift Package Manager.
// Below is the original copyright claim and licensing information.
/*
 This source file is part of the Swift.org open source project
 Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
 Licensed under Apache License v2.0 with Runtime Library Exception
 See http://swift.org/LICENSE.txt for license information
 See http://swift.org/CONTRIBUTORS.txt for Swift project authors
*/

// All modifications are (c) 2017 Sid Mani and are licensed under the same Apache License v2.0 with Runtime Library Exception.

import Foundation

public final class BTC_SHA256 {
    var second_block_intermediaries: [[UInt32]] = []
    /// The length of the output digest (in bits).
    let digestLength = 256

    /// The size of each blocks (in bits).
    let blockBitSize = 512

    /// The initial hash value.
    static let initalHashValue: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    /// The constants in the algorithm (K).
    static let konstants: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    // to be reused each nonce
    var hash = BTC_SHA256.initalHashValue
    var hashAfter3rdIteration = BTC_SHA256.initalHashValue

    var secondBlock_W = [UInt32](repeating: 0, count: BTC_SHA256.konstants.count)
    var thirdBlock_W = [UInt32](repeating: 0, count: BTC_SHA256.konstants.count)
    let secondHash = BTC_SHA256.initalHashValue

    // W constant intermediates
    var secondBlock_W_18_base: UInt32 = 0
    var secondBlock_W_19_base: UInt32 = 0
    var secondBlock_W_31_base: UInt32 = 0
    var secondBlock_W_32_base: UInt32 = 0

    // algorithm intermediates
    var round4_b_c: UInt32 = 0
    var round4_t1_base: UInt32 = 0
    var round4_e_base: UInt32 = 0

    var round5_t1_base: UInt32 = 0

    var round6_t1_base: UInt32 = 0
    /// The input that was provided. It will be padded when computing the digest.
    var input: [UInt8]

    public init(_ _input: [UInt8]) {
        self.input = _input
        process(W: calculateW(of: self.input[0..<64]),
                hashInitial: &hash)

        generate_second_block_W_constants()
        generate_second_block_precomputed_values()
        generate_third_block_W_constants()
    }

    func hashWithNonce(nonce: UInt32) -> [UInt32]? {
        // second block W calculation with precomputed values
        calculate_second_block_W(nonce: nonce)
        second_block_main_algorithm(nonce: nonce)

        // compute third block

        calculate_third_block_W()
        return third_block_probe() ? third_block_full_hash() : nil
    }

    // naive calculation used only for zero block
    func calculateW(of block: ArraySlice<UInt8>) -> [UInt32] {
        var W = [UInt32](repeating: 0, count: BTC_SHA256.konstants.count)
        for t in 0..<W.count {
            switch t {
            case 0...15:
                let index = block.startIndex.advanced(by: t * 4)
                // Put 4 bytes in each message.
                W[t]  = UInt32(block[index + 0]) << 24
                W[t] |= UInt32(block[index + 1]) << 16
                W[t] |= UInt32(block[index + 2]) << 8
                W[t] |= UInt32(block[index + 3])
            default:
                let σ1 = W[t-2].rotateRight(by: 17) ^ W[t-2].rotateRight(by: 19) ^ (W[t-2] >> 10)
                let σ0 = W[t-15].rotateRight(by: 7) ^ W[t-15].rotateRight(by: 18) ^ (W[t-15] >> 3)
                W[t] = σ1 &+ W[t-7] &+ σ0 &+ W[t-16]
            }
        }
        return W
    }

    /// Process and compute hash from a block.
    func process(W: [UInt32],
                 hashInitial: inout [UInt32]) {

        var a = hashInitial[0]
        var b = hashInitial[1]
        var c = hashInitial[2]
        var d = hashInitial[3]
        var e = hashInitial[4]
        var f = hashInitial[5]
        var g = hashInitial[6]
        var h = hashInitial[7]

        // Run the main algorithm.
        for t in 0..<64 {
            executeAlgorithmOnce(a: &a, b: &b, c: &c, d: &d, e: &e, f: &f, g: &g, h: &h, iteration: t, W: W)
        }

        hashInitial[0] = a &+ hashInitial[0]
        hashInitial[1] = b &+ hashInitial[1]
        hashInitial[2] = c &+ hashInitial[2]
        hashInitial[3] = d &+ hashInitial[3]
        hashInitial[4] = e &+ hashInitial[4]
        hashInitial[5] = f &+ hashInitial[5]
        hashInitial[6] = g &+ hashInitial[6]
        hashInitial[7] = h &+ hashInitial[7]
    }

    func executeAlgorithmOnce(a: inout UInt32,
                              b: inout UInt32,
                              c: inout UInt32,
                              d: inout UInt32,
                              e: inout UInt32,
                              f: inout UInt32,
                              g: inout UInt32,
                              h: inout UInt32,
                              iteration t: Int,
                              W: [UInt32]) {
        let Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        let ch = (e & f) ^ (~e & g)
        let t1 = h &+ Σ1 &+ ch &+ BTC_SHA256.konstants[t] &+ W[t]

        let Σ0 = a.rotateRight(by: 2) ^ a.rotateRight(by: 13) ^ a.rotateRight(by: 22)
        let maj = (a & b) ^ (a & c) ^ (b & c)
        let t2 = Σ0 &+ maj

        h = g
        g = f
        f = e
        e = d &+ t1
        d = c
        c = b
        b = a
        a = t1 &+ t2
    }
}

extension UInt32 {
    /// Rotates self by given amount.
    func rotateRight(by amount: UInt32) -> UInt32 {
        return (self >> amount) ^ (self << (32 - amount))
    }
}
