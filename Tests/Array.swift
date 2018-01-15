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


import XCTest


extension Array where Element == UInt8 {
    
    init?(hexString: String)
    {
        if let bytes = [UInt8].fromHexString(hexString) {
            self.init(bytes)
        }
        else {
            return nil
        }
    }
    
    private static func fromHexString(_ string: String) -> [UInt8]?
    {
        guard((string.count % 2) == 0) else { return nil }
        
        var bytes = [UInt8]()
        var index = string.startIndex
        let count = string.count / 2
        
        for _ in 0..<count {
            let next = string.index(index, offsetBy: 2)
            
            if let byte = UInt8(String(string[index..<next]), radix: 16) {
                bytes.append(byte)
            }
            else {
                return nil
            }
            
            index = next
        }
        
        return bytes
    }
    
}


// End of File
