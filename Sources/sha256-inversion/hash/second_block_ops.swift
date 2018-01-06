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
extension BTC_SHA256 {
    // ONCE
    func generate_second_block_W_constants() {
        // last 32 bits of merkle root
        secondBlock_W[0]  = UInt32(input[64]) << 24
        secondBlock_W[0] |= UInt32(input[65]) << 16
        secondBlock_W[0] |= UInt32(input[66]) << 8
        secondBlock_W[0] |= UInt32(input[67])

        // timestamp
        secondBlock_W[1]  = UInt32(input[68]) << 24
        secondBlock_W[1] |= UInt32(input[69]) << 16
        secondBlock_W[1] |= UInt32(input[70]) << 8
        secondBlock_W[1] |= UInt32(input[71])

        // bits
        secondBlock_W[2]  = UInt32(input[72]) << 24
        secondBlock_W[2] |= UInt32(input[73]) << 16
        secondBlock_W[2] |= UInt32(input[74]) << 8
        secondBlock_W[2] |= UInt32(input[75])

        // padding start and end
    //    secondBlock_W[4] = 0x80000000
        // 5...14 are zeros
    //    secondBlock_W[15] = 0x00000280

        // round 16
        var σ0 = secondBlock_W[1].rotateRight(by: 7) ^ secondBlock_W[1].rotateRight(by: 18) ^ (secondBlock_W[1] >> 3)
        secondBlock_W[16] = σ0 &+ secondBlock_W[0]

        // round 17
        σ0 = secondBlock_W[2].rotateRight(by: 7) ^ secondBlock_W[2].rotateRight(by: 18) ^ (secondBlock_W[2] >> 3)
        secondBlock_W[17] = 0x01100000 &+ σ0 &+ secondBlock_W[1]

        // round 18
        secondBlock_W_18_base = secondBlock_W[16].rotateRight(by: 17) ^ secondBlock_W[16].rotateRight(by: 19) ^ (secondBlock_W[16] >> 10) &+ secondBlock_W[2]

        // round 19
        // needs &+ nonce
        secondBlock_W_19_base = secondBlock_W[17].rotateRight(by: 17) ^ secondBlock_W[17].rotateRight(by: 19) ^ (secondBlock_W[17] >> 10) &+ 0x11002000 //&+ secondBlock_W[19-16]

        // round 31
        secondBlock_W_31_base = secondBlock_W[16].rotateRight(by: 7) ^ secondBlock_W[16].rotateRight(by: 18) ^ (secondBlock_W[16] >> 3) &+ 0x00000280

        // round 32
        secondBlock_W_32_base = secondBlock_W[17].rotateRight(by: 7) ^ secondBlock_W[17].rotateRight(by: 18) ^ (secondBlock_W[17] >> 3) &+ secondBlock_W[16]
    }

    func generate_second_block_precomputed_values() {
        // rounds 0-2 are not dependent on the nonce
        var a = hash[0]
        var b = hash[1]
        var c = hash[2]
        var d = hash[3]
        var e = hash[4]
        var f = hash[5]
        var g = hash[6]
        var h = hash[7]

        for t in 0..<4 {
            executeAlgorithmOnce(a: &a, b: &b, c: &c, d: &d, e: &e, f: &f, g: &g, h: &h, iteration: t, W: secondBlock_W)
        }

        hashAfter3rdIteration = [a, b, c, d, e, f, g, h]
        // round 4 precompute
        round4_b_c = b & c
        round4_t1_base = hashAfter3rdIteration[7] &+ 0xB956C25B

        // round 5 precompute
        round5_t1_base = hashAfter3rdIteration[6] &+ BTC_SHA256.konstants[5]

        // round 6 precompute
        round6_t1_base = hashAfter3rdIteration[5] &+ BTC_SHA256.konstants[6]
    }

    // EVERY NONCE
    func calculate_second_block_W(nonce: UInt32) {
        var σ1: UInt32
        // 3
        secondBlock_W[3] = nonce
        // 18
        var σ0 = nonce.rotateRight(by: 7) ^ nonce.rotateRight(by: 18) ^ (nonce >> 3)
        secondBlock_W[18] = σ0 &+ secondBlock_W_18_base

        // 19
        secondBlock_W[19] = secondBlock_W_19_base &+ nonce

        // 20
        σ1 = secondBlock_W[18].rotateRight(by: 17) ^ secondBlock_W[18].rotateRight(by: 19) ^ (secondBlock_W[18] >> 10)
        secondBlock_W[20] = σ1 &+ 0x80000000

        // 21
        secondBlock_W[21] = secondBlock_W[19].rotateRight(by: 17) ^ secondBlock_W[19].rotateRight(by: 19) ^ (secondBlock_W[19] >> 10)

        // 22
        σ1 = secondBlock_W[20].rotateRight(by: 17) ^ secondBlock_W[20].rotateRight(by: 19) ^ (secondBlock_W[20] >> 10)
        secondBlock_W[22] = σ1 &+ 0x00000280

        for t in 23..<30 {
            σ1 = secondBlock_W[t-2].rotateRight(by: 17) ^ secondBlock_W[t-2].rotateRight(by: 19) ^ (secondBlock_W[t-2] >> 10)
            secondBlock_W[t] = σ1 &+ secondBlock_W[t-7]
        }

        // 30
        σ1 = secondBlock_W[28].rotateRight(by: 17) ^ secondBlock_W[28].rotateRight(by: 19) ^ (secondBlock_W[28] >> 10)
        secondBlock_W[30] = σ1 &+ secondBlock_W[23] &+ 0x00A00055

        // 31
        σ1 = secondBlock_W[29].rotateRight(by: 17) ^ secondBlock_W[29].rotateRight(by: 19) ^ (secondBlock_W[29] >> 10)
        secondBlock_W[31] = σ1 &+ secondBlock_W[24] &+ secondBlock_W_31_base

        // 32
        σ1 = secondBlock_W[30].rotateRight(by: 17) ^ secondBlock_W[30].rotateRight(by: 19) ^ (secondBlock_W[30] >> 10)
        secondBlock_W[32] = σ1 &+ secondBlock_W[25] &+ secondBlock_W_32_base

        for t in 33..<secondBlock_W.count {
            σ1 = secondBlock_W[t-2].rotateRight(by: 17) ^ secondBlock_W[t-2].rotateRight(by: 19) ^ (secondBlock_W[t-2] >> 10)
            σ0 = secondBlock_W[t-15].rotateRight(by: 7) ^ secondBlock_W[t-15].rotateRight(by: 18) ^ (secondBlock_W[t-15] >> 3)
            secondBlock_W[t] = σ1 &+ secondBlock_W[t-7] &+ σ0 &+ secondBlock_W[t-16]
        }
    }

    func second_block_main_algorithm(nonce: UInt32) {
        var a = hashAfter3rdIteration[0] &+ nonce
        var b = hashAfter3rdIteration[1]
        var c = hashAfter3rdIteration[2]
        var d: UInt32
        var e = hashAfter3rdIteration[4] &+ nonce
        var f = hashAfter3rdIteration[5]
        var g = hashAfter3rdIteration[6]
        var h: UInt32
        // Run the main algorithm.

        // iteration 4
        var Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        var ch = (e & f) ^ (~e & g)
        var t1 = round4_t1_base &+ Σ1 &+ ch

        var Σ0 = a.rotateRight(by: 2) ^ a.rotateRight(by: 13) ^ a.rotateRight(by: 22)
        var maj = (a & b) ^ (a & c) ^ round4_b_c // precompute b & c
        var t2 = Σ0 &+ maj

        h = g
        g = f
        f = e
        e = hashAfter3rdIteration[3] &+ t1
        d = c
        c = b
        b = a
        a = t1 &+ t2
        //   second_block_intermediaries.append([a, b, c, d, e, f, g, h])

        // iteration 5
        Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        ch = (e & f) ^ (~e & g)
        t1 = round5_t1_base &+ Σ1 &+ ch

        Σ0 = a.rotateRight(by: 2) ^ a.rotateRight(by: 13) ^ a.rotateRight(by: 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = Σ0 &+ maj

        h = g
        g = f
        f = e
        e = d &+ t1
        d = c
        c = b
        b = a
        a = t1 &+ t2
        //  second_block_intermediaries.append([a, b, c, d, e, f, g, h])

        // iteration 6
        Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        ch = (e & f) ^ (~e & g)
        t1 = round6_t1_base &+ Σ1 &+ ch

        Σ0 = a.rotateRight(by: 2) ^ a.rotateRight(by: 13) ^ a.rotateRight(by: 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = Σ0 &+ maj

        h = g
        g = f
        f = e
        e = d &+ t1
        d = c
        c = b
        b = a
        a = t1 &+ t2

        for t in 7..<15 {
            let Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
            let ch = (e & f) ^ (~e & g)
            let t1 = h &+ Σ1 &+ ch &+ BTC_SHA256.konstants[t] // no need to add W[t] b/c it's zero

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

        // iteration 15
        Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        ch = (e & f) ^ (~e & g)
        t1 = h &+ Σ1 &+ ch &+ 0xc19bf3f4 // uses constant value W[15] (end of padding)

        Σ0 = a.rotateRight(by: 2) ^ a.rotateRight(by: 13) ^ a.rotateRight(by: 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = Σ0 &+ maj

        h = g
        g = f
        f = e
        e = d &+ t1
        d = c
        c = b
        b = a
        a = t1 &+ t2

        for t in 16..<64 {
            executeAlgorithmOnce(a: &a, b: &b, c: &c, d: &d, e: &e, f: &f, g: &g, h: &h, iteration: t, W: secondBlock_W)
        }

        thirdBlock_W[0] = a &+ hash[0]
        thirdBlock_W[1] = b &+ hash[1]
        thirdBlock_W[2] = c &+ hash[2]
        thirdBlock_W[3] = d &+ hash[3]
        thirdBlock_W[4] = e &+ hash[4]
        thirdBlock_W[5] = f &+ hash[5]
        thirdBlock_W[6] = g &+ hash[6]
        thirdBlock_W[7] = h &+ hash[7]
    }
}
