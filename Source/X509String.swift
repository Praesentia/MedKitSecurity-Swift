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
 X509 String
 
 - Requirement: RFC-5280
 */
extension X509String: DERCodable {
    
    // MARK: - Initializers
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    init(decoder: DERDecoder) throws
    {
        switch try decoder.peekTag() {
        case DERCoder.TagIA5String :
            let bytes: [UInt8] = try decoder.decodeIA5String()
            self.init(bytes: bytes, encoding: .ia5)
        
        case DERCoder.TagPrintableString :
            let bytes: [UInt8] = try decoder.decodePrintableString()
            self.init(bytes: bytes, encoding: .printable)
            
        case DERCoder.TagUTF8String :
            let bytes: [UInt8] = try decoder.decodeUTF8String()
            self.init(bytes: bytes, encoding: .utf8)
            
        default :
            throw SecurityKitError.failed
        }
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        switch encoding {
        case .ia5 :
            return encoder.encodeIA5String(encoded)
        
        case .printable :
            return encoder.encodePrintableString(encoded)
            
        case .utf8 :
            return encoder.encodeUTF8String(encoded)
        }
    }
    
}


// End of File
