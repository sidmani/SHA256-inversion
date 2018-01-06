import Foundation
func benchmark(fn: () -> ()) -> CFTimeInterval {
    let start = CFAbsoluteTimeGetCurrent()
    fn()
    return CFAbsoluteTimeGetCurrent() - start
}

func benchmark(iter: UInt32, fn: (UInt32) -> ()) -> CFTimeInterval {
    var avg: CFTimeInterval = 0
    for i in 0..<iter {
        let start = CFAbsoluteTimeGetCurrent()
        fn(i)
        let end = CFAbsoluteTimeGetCurrent()
        avg += (end - start) / Double(iter)
    }
    return avg
}

extension UInt32 {
    /// Rotates self by given amount.
    func rotateRight(by amount: UInt32) -> UInt32 {
        return (self >> amount) ^ (self << (32 - amount))
    }
}


