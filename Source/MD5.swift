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


import CommonCrypto
import Foundation
import SecurityKit


/**
 MD5 digest.
 */
class MD5: Digest {
    
    // MARK: - Private Properties
    private var context = CC_MD5_CTX()
    
    // MARK: - Initializers
    
    public init()
    {
        CC_MD5_Init(&context)
    }
    
    // MARK: -
    
    public func reset()
    {
        CC_MD5_Init(&context)
    }
    
    public func final() -> Data
    {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        
        CC_MD5_Final(&digest, &context)
        CC_MD5_Init(&context)
        
        return Data(digest)
    }
    
    public func update(bytes: [UInt8])
    {
        CC_MD5_Update(&context, bytes, CC_LONG(bytes.count))
    }
    
}


// End of File
