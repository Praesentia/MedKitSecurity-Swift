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


import CommonCrypto
import Foundation
import SecurityKit


/**
 SHA1 HMAC
 */
class HMACSHA1: HMAC {
    
    // MARK: - Private Properties∫
    private static let algorithm = CCHmacAlgorithm(kCCHmacAlgSHA1)
    static let         size      = Int(CC_SHA1_DIGEST_LENGTH)
    
    // MARK: -
    
    func sign(bytes: [UInt8], using secret: [UInt8]) -> [UInt8]
    {
        var output = [UInt8](repeating: 0, count: HMACSHA1.size)
        
        CCHmac(HMACSHA1.algorithm, secret, secret.count, bytes, bytes.count, &output)
        
        return output
    }
    
}


// End of File