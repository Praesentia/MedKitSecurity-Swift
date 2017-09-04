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
class PrivateKeyRSA: PrivateKey {
    
    // MARK: - Properties
    public let algorithm = X509Algorithm.rsaEncryption
    public var keySize   : UInt { return 0 }
    
    // MARK: Internal Properties
    let key: SecKey
    
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
    
    func sign(bytes: [UInt8], using digestType: DigestType) -> [UInt8]
    {
        let digest = instantiateDigest(ofType: digestType)
        let hash   = digest.hash(bytes: bytes)
        return key.sign(bytes: hash, padding: digestType.padding)!
    }
    
    func verify(signature: [UInt8], for bytes: [UInt8], using digestType: DigestType) -> Bool
    {
        let digest = instantiateDigest(ofType: digestType)
        return key.verify(signature: signature, for: digest.hash(bytes: bytes), padding: digestType.padding)
    }
    
}


// End of File

