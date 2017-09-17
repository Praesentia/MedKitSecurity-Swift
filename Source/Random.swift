/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
 Copyright 2017 Jon Griffeth
 
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

}


// End of File
