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


extension X509SubjectPublicKeyInfo: DERCodable {
    
    // MARK: - Initializers
    
    init(subjectPublicKey: SecKey)
    {
        self.algorithm        = X509Algorithm.rsaEncryption
        self.subjectPublicKey = X509PublicKey(data: subjectPublicKey.data!)
    }
    
    init(decoder: DERDecoder) throws
    {
        algorithm        = try X509Algorithm(decoder: decoder.decoderFromSequence())
        subjectPublicKey = try X509PublicKey(decoder: decoder)
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        var bytes = [UInt8]()
        
        bytes += encoder.encode(algorithm)
        bytes += encoder.encode(subjectPublicKey)
            
        return encoder.encodeSequence(bytes: bytes)
    }
    
}


// End of File
