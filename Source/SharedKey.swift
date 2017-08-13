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
 Shared Key
 */
class SharedKey: Key {
    
    // MARK: - Properties
    public var blockSize: Int  { return HMACSHA256.size }
    public var keySize  : UInt { return UInt(secret.count) * 8 }
    
    // MARK: Private Properties
    private let secret: [UInt8]
    
    // MARK: - Initializers
    
    init(with secret: [UInt8])
    {
        self.secret = secret
    }
    
    // MARK: - Signing
    
    func sign(bytes: [UInt8], using digestType: DigestType) -> [UInt8]
    {
        let hmac = HMACSHA256()

        return hmac.sign(bytes: bytes, using: secret)
    }
    
    func sign(bytes: [UInt8], padding: DigestType) -> [UInt8]
    {
        let hmac = HMACSHA256()
        return hmac.sign(bytes: bytes, using: secret)
    }
    
    func verify(signature: [UInt8], for bytes: [UInt8], padding digestType: DigestType) -> Bool
    {
        let hmac = HMACSHA256()
        return signature == hmac.sign(bytes: bytes, using: secret)
    }
    
    func verify(signature: [UInt8], for bytes: [UInt8], using digestType: DigestType) -> Bool
    {
        let hmac = instantiateHMAC(using: digestType)
        return signature == hmac.sign(bytes: bytes, using: secret)
    }
    
}


// End of File
