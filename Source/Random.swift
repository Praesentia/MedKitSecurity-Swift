/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
 Copyright 2017-2018 Jon Griffeth
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 -----------------------------------------------------------------------------
 */


import Foundation


/**
 Secure random number generator.
 */
class Random {

    static func value(_ type: Int.Type) -> Int
    {
        return integer(Int.self)
    }

    static func value(_ type: UInt.Type) -> UInt
    {
        return integer(UInt.self)
    }

    static func value(_ type: UInt8.Type) -> UInt8
    {
        return integer(UInt8.self)
    }

    static func value(_ type: UInt16.Type) -> UInt16
    {
        return integer(UInt16.self)
    }

    static func value(_ type: UInt32.Type) -> UInt32
    {
        return integer(UInt32.self)
    }

    static func value(_ type: UInt64.Type) -> UInt64
    {
        return integer(UInt64.self)
    }

    /**
     Generate random bytes.
     
     - Parameters:
        - count: Number of bytes requested.
     
     - Returns:
        Returns an array of count bytes.
     */
    static func bytes(count: Int) -> [UInt8]
    {
        var bytes  = [UInt8](repeating: 0, count: count)
        var status : Int32
        
        status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess { // TODO: Under what circumstances would this occur?
            fatalError("Unexpected error.")
        }
        
        return bytes
    }

    private static func integer<T: ExpressibleByIntegerLiteral>(_ type: T.Type) -> T
    {
        var value: T = 0

        withUnsafeMutablePointer(to: &value) {
            let status = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<T>.size, $0)
            if status != errSecSuccess { // TODO: Under what circumstances would this occur?
                fatalError("Unexpected error.")
            }
        }

        return value
    }

}


// End of File
