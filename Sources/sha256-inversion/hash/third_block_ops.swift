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
    func generate_third_block_W_constants() {
        thirdBlock_W[8] = 0x80000000
        thirdBlock_W[15] = 0x00000100
    }

    func calculate_third_block_W() {
        var σ1: UInt32 = 0
        var σ0: UInt32 = 0

        thirdBlock_W[16] = thirdBlock_W[1].rotateRight(by: 7) ^ thirdBlock_W[1].rotateRight(by: 18) ^ (thirdBlock_W[1] >> 3) &+ thirdBlock_W[0]

        // 17
        σ0 = thirdBlock_W[2].rotateRight(by: 7) ^ thirdBlock_W[2].rotateRight(by: 18) ^ (thirdBlock_W[2] >> 3)
        thirdBlock_W[17] = 0x00a00000 &+ σ0 &+ thirdBlock_W[1]

        // 18 19 20 21
        for t in 18..<22 {
            σ1 = thirdBlock_W[t-2].rotateRight(by: 17) ^ thirdBlock_W[t-2].rotateRight(by: 19) ^ (thirdBlock_W[t-2] >> 10)
            σ0 = thirdBlock_W[t-15].rotateRight(by: 7) ^ thirdBlock_W[t-15].rotateRight(by: 18) ^ (thirdBlock_W[t-15] >> 3)
            thirdBlock_W[t] = σ1 &+ σ0 &+ thirdBlock_W[t-16] //18-21: t-7 -> 0
        }

        // 22
        σ1 = thirdBlock_W[20].rotateRight(by: 17) ^ thirdBlock_W[20].rotateRight(by: 19) ^ (thirdBlock_W[20] >> 10)
        σ0 = thirdBlock_W[7].rotateRight(by: 7) ^ thirdBlock_W[7].rotateRight(by: 18) ^ (thirdBlock_W[7] >> 3)
        thirdBlock_W[22] = σ1 &+ 0x00000100 &+ σ0 &+ thirdBlock_W[6]

        // 23
        σ1 = thirdBlock_W[21].rotateRight(by: 17) ^ thirdBlock_W[21].rotateRight(by: 19) ^ (thirdBlock_W[21] >> 10)
        thirdBlock_W[23] = σ1 &+ thirdBlock_W[16] &+ 0x11002000 &+ thirdBlock_W[7]

        for t in 24..<30 {
            σ1 = thirdBlock_W[t-2].rotateRight(by: 17) ^ thirdBlock_W[t-2].rotateRight(by: 19) ^ (thirdBlock_W[t-2] >> 10)
            thirdBlock_W[t] = σ1 &+ thirdBlock_W[t-7] &+ thirdBlock_W[t-16]
        }

        // 30
        σ1 = thirdBlock_W[28].rotateRight(by: 17) ^ thirdBlock_W[28].rotateRight(by: 19) ^ (thirdBlock_W[28] >> 10)
        thirdBlock_W[30] = σ1 &+ thirdBlock_W[23] &+ 0x00400022

        // 31
        σ1 = thirdBlock_W[29].rotateRight(by: 17) ^ thirdBlock_W[29].rotateRight(by: 19) ^ (thirdBlock_W[29] >> 10)
        σ0 = thirdBlock_W[16].rotateRight(by: 7) ^ thirdBlock_W[16].rotateRight(by: 18) ^ (thirdBlock_W[16] >> 3)
        thirdBlock_W[31] = σ1 &+ thirdBlock_W[24] &+ σ0 &+ 0x00000100

        for t in 32..<61 {
            σ1 = thirdBlock_W[t-2].rotateRight(by: 17) ^ thirdBlock_W[t-2].rotateRight(by: 19) ^ (thirdBlock_W[t-2] >> 10)
            σ0 = thirdBlock_W[t-15].rotateRight(by: 7) ^ thirdBlock_W[t-15].rotateRight(by: 18) ^ (thirdBlock_W[t-15] >> 3)
            thirdBlock_W[t] = σ1 &+ thirdBlock_W[t-7] &+ σ0 &+ thirdBlock_W[t-16]
        }
    }

    func third_block_full_hash() -> [UInt32] {
        // only needed for complete hash, not nonce check
        for t in 61..<64 {
            let σ1 = thirdBlock_W[t-2].rotateRight(by: 17) ^ thirdBlock_W[t-2].rotateRight(by: 19) ^ (thirdBlock_W[t-2] >> 10)
            let σ0 = thirdBlock_W[t-15].rotateRight(by: 7) ^ thirdBlock_W[t-15].rotateRight(by: 18) ^ (thirdBlock_W[t-15] >> 3)
            thirdBlock_W[t] = σ1 &+ thirdBlock_W[t-7] &+ σ0 &+ thirdBlock_W[t-16]
        }

        var a = secondHash[0]
        var b = secondHash[1]
        var c = secondHash[2]
        var d = secondHash[3]
        var e = secondHash[4]
        var f = secondHash[5]
        var g = secondHash[6]
        var h = secondHash[7]

        for t in 0..<64 {
            let Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
            let ch = (e & f) ^ (~e & g)
            let t1 = h &+ Σ1 &+ ch &+ BTC_SHA256.konstants[t] &+ thirdBlock_W[t]

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

        return [a &+ secondHash[0],
                b &+ secondHash[1],
                c &+ secondHash[2],
                d &+ secondHash[3],
                e &+ secondHash[4],
                f &+ secondHash[5],
                g &+ secondHash[6],
                h &+ secondHash[7]]
    }


    func third_block_probe() -> Bool {
        var a = secondHash[0]
        var b = secondHash[1]
        var c = secondHash[2]
        var d = secondHash[3]
        var e = secondHash[4]
        var f = secondHash[5]
        var g = secondHash[6]
        var h = secondHash[7]

        var Σ1: UInt32 = 0
        var ch: UInt32 = 0
        var t1: UInt32 = 0
        var Σ0: UInt32 = 0
        var maj: UInt32 = 0
        var t2: UInt32 = 0

        for t in 0..<8 {
            Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
            ch = (e & f) ^ (~e & g)
            t1 = h &+ Σ1 &+ ch &+ BTC_SHA256.konstants[t] &+ thirdBlock_W[t]

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
        }
        // 8
        Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        ch = (e & f) ^ (~e & g)
        t1 = h &+ Σ1 &+ ch &+ 0x5807aa98

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

        for t in 9..<15 {
            Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
            ch = (e & f) ^ (~e & g)
            t1 = h &+ Σ1 &+ ch &+ BTC_SHA256.konstants[t]

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
        }

        // 15
        Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        ch = (e & f) ^ (~e & g)
        t1 = h &+ Σ1 &+ ch &+ 0xc19bf274

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

        for t in 16..<57 {
            Σ1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
            ch = (e & f) ^ (~e & g)
            t1 = h &+ Σ1 &+ ch &+ BTC_SHA256.konstants[t] &+ thirdBlock_W[t]

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
        }

        let ch_57 = (e & f) ^ (~e & g)
        let sigma1_57 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
        let t1_57 = h &+ sigma1_57 &+ ch_57 &+ BTC_SHA256.konstants[57] &+ thirdBlock_W[57]
        let e_57 = d &+ t1_57

        let ch_58 = (e_57 & e) ^ (~e_57 & f)
        let sigma1_58 = e_57.rotateRight(by: 6) ^ e_57.rotateRight(by: 11) ^ e_57.rotateRight(by: 25)
        let t1_58 = g &+ sigma1_58 &+ ch_58 &+ BTC_SHA256.konstants[58] &+ thirdBlock_W[58]
        let e_58 = c &+ t1_58

        let ch_59 = (e_58 & e_57) ^ (~e_58 & e)
        let sigma1_59 = e_58.rotateRight(by: 6) ^ e_58.rotateRight(by: 11) ^ e_58.rotateRight(by: 25)
        let t1_59 = f &+ sigma1_59 &+ ch_59 &+ BTC_SHA256.konstants[59] &+ thirdBlock_W[59]
        let e_59 = b &+ t1_59

        let ch_60 = (e_59 & e_58) ^ (~e_59 & e_57)
        let sigma1_60 = e_59.rotateRight(by: 6) ^ e_59.rotateRight(by: 11) ^ e_59.rotateRight(by: 25)

        return (a &+
            e &+
            sigma1_60 &+
            ch_60 &+
            thirdBlock_W[60] &+
            0xEC9FCD13 == 0)
    }
}
