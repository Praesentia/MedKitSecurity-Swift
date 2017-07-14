/*
 -----------------------------------------------------------------------------
 This source file is part of MedKitSecurity.
 
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
import SecurityKit


/**
 Private Key
 */
class PrivateKey: Key {
    
    // MARK: - Properties
    public var blockSize: Int { return SecKeyGetBlockSize(key) }
    
    // MARK: Private Properties
    private let key: SecKey
    
    // MARK: - Initializers
    
    init(_ key: SecKey)
    {
        self.key = key
    }
    
    convenience init?(_ key: SecKey?)
    {
        if key != nil {
            self.init(key!)
        }
        else {
            return nil
        }
    }
    
    // MARK: - Signing
    
    func sign(bytes: [UInt8], padding digest: DigestType) -> [UInt8]
    {
        return key.sign(bytes: bytes, padding: digest.padding)!
    }
    
    func verify(signature: [UInt8], padding digest: DigestType, for bytes: [UInt8]) -> Bool
    {
        return key.verify(signature: signature, padding: digest.padding, for: bytes)
    }
    
    func verify(signature: [UInt8], using digestType: DigestType, for data: Data) -> Bool
    {
        let digest  = instantiateDigest(ofType: digestType)
        
        digest.update(data: data)
        
        return key.verify(signature: signature, padding: digestType.padding, for: digest.final())
    }
    
}


// End of File
