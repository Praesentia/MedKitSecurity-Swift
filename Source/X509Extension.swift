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
 X509 Extension
 
 - Requirement: RFC-5280, 4.1
 */
struct X509Extension {
    
    // MARK: - Properties
    var extnID    : [UInt]
    var critical  : Bool
    var extnValue : [UInt8]
    
    // MARK: - Initializers
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    init(decoder: DERDecoder) throws
    {
        extnID    = try decoder.decodeObjectIdentifier()
        
        if try decoder.peekTag() == DERCoder.TagBoolean {
            critical = try decoder.decodeBoolean()
        }
        else {
            critical = false
        }
        
        extnValue = try decoder.decodeOctetString()
        
        try decoder.assertAtEnd()
    }
    
}


// End of File
