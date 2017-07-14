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
 X509 Extension
 */
extension X509PublicKey: DERCodable {
    
    // MARK: - Initializers
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    init(decoder: DERDecoder) throws
    {
        let bytes   = try decoder.decodeBitString()
        let decoder = try DERDecoder(bytes: bytes[1..<bytes.count]).decoderFromSequence()
        
        let modulus  = try decoder.decodeUnsignedInteger()
        let exponent = try decoder.decodeUnsignedInteger()
        try decoder.assertAtEnd()
        
        self.init(data: Data(decoder.bytes), modulus: modulus, exponent: exponent)
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        return encoder.encodeBitString(bytes: [0] + [UInt8](data))
    }
    
}


// End of File

