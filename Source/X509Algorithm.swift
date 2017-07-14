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


extension X509Algorithm: DERCodable {
    
    // MARK: - Initializers
    
    init(decoder: DERDecoder) throws
    {
        let oid        = try OID(decoder: decoder)
        let parameters = try decoder.decodeNull()
        try decoder.assertAtEnd()
        
        self.init(oid: oid, parameters: parameters)
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        var bytes = [UInt8]()
        
        bytes += encoder.encode(oid)
        bytes += encoder.encodeNull()
        
        return encoder.encodeSequence(bytes: bytes)
    }
    
}


// End of File
