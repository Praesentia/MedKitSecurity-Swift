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


/**
 X509 String
 
 - Requirement: RFC-5280
 */
struct X509String: DERCodable, Equatable {
    
    enum StringType {
        case ia5
        case printable
        case utf8
    }
    
    // MARK: - Properties
    var type   : StringType
    var string : String
    
    // MARK: - Initializers
    
    /**
     Initialize instance from extension.
     */
    init(string: String)
    {
        self.type   = .printable
        self.string = string
    }
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    init(decoder: DERDecoder) throws
    {
        switch try decoder.peekTag() {
        case DERCoder.TagIA5String :
            type   = .ia5
            string = try decoder.decodeIA5String()
        
        case DERCoder.TagPrintableString :
            type   = .printable
            string = try decoder.decodePrintableString()
            
        case DERCoder.TagUTF8String :
            type   = .utf8
            string = try decoder.decodeUTF8String()
            
        default :
            throw MedKitError.failed
        }
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        switch type {
        case .ia5 :
            return encoder.encodeIA5String(string)
        
        case .printable :
            return encoder.encodePrintableString(string)
            
        case .utf8 :
            return encoder.encodeUTF8String(string)
        }
    }
    
}

func ==(lhs: X509String, rhs: X509String) -> Bool
{
    return lhs.string == rhs.string
}


// End of File
