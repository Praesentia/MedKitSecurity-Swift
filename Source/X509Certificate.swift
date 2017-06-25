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


struct X509Certificate: DERCodable {
    
    var tbsCertificate : X509TBSCertificate
    var algorithm      : X509Algorithm
    var signature      : [UInt8]
    
    init(tbsCertificate: X509TBSCertificate, algorithm: X509Algorithm, signature: [UInt8])
    {
        self.tbsCertificate = tbsCertificate
        self.algorithm      = algorithm
        self.signature      = signature
    }
    
    init(from data: Data) throws
    {
        let decoder  = DERDecoder(bytes: [UInt8](data))
        let sequence = try decoder.decoderFromSequence()
        try decoder.assertAtEnd()
        
        try self.init(decoder: sequence)
    }
    
    init(decoder: DERDecoder) throws
    {
        tbsCertificate = try X509TBSCertificate(decoder: try decoder.decoderFromSequence())
        algorithm      = try X509Algorithm(decoder: try decoder.decoderFromSequence())
        let s  = try decoder.decodeBitString()
        signature      = Array(s[1..<257])
        
        try decoder.assertAtEnd()
    }
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        var bytes = [UInt8]()
        
        bytes += encoder.encode(tbsCertificate)
        bytes += encoder.encode(algorithm)
        bytes += encoder.encodeBitString(bytes: [0] + signature)
        
        return encoder.encodeSequence(bytes: bytes)
    }
    
}


// End of File
