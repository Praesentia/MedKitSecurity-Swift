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
import MedKitCore


struct X509SubjectPublicKeyInfo: DERCodable {
    
    // MARK: - Properties
    var algorithm        : X509Algorithm
    var subjectPublicKey : [UInt8]
    
    // MARK: - Initializers
    
    init(subjectPublicKey: SecKey)
    {
        self.algorithm        = X509Algorithm.rsaEncryption
        self.subjectPublicKey = [UInt8](subjectPublicKey.data!)
    }
    
    init(algorithm: X509Algorithm, subjectPublicKey: [UInt8])
    {
        self.algorithm        = algorithm
        self.subjectPublicKey = subjectPublicKey
    }
    
    init(decoder: DERDecoder) throws
    {
        algorithm = try X509Algorithm(decoder: decoder.decoderFromSequence())
        
        let bytes = try decoder.decodeBitString()
        
        subjectPublicKey = Array(bytes[1..<bytes.count])
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        var bytes = [UInt8]()
        
        bytes += encoder.encode(algorithm)
        bytes += encoder.encodeBitString(bytes: [0] + subjectPublicKey)
            
        return encoder.encodeSequence(bytes: bytes)
    }
    
}


// End of File
