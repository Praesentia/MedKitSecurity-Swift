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
 X509 Extended Key Usage
 
 - Requirement: RFC-5280
 */
extension X509ExtendedKeyUsage {
    
    // MARK: - Initializers
    
    /**
     Initialize instance from extension.
     */
    init(from extn: X509Extension) throws
    {
        let decoder  = DERDecoder(bytes: extn.extnValue)
        let sequence = try decoder.decoderFromSequence()
        try decoder.assertAtEnd()
        
        purposeIdentifiers = []
        
        repeat {
            let purposeIdentifier = try sequence.decodeObjectIdentifier()
            purposeIdentifiers.append(purposeIdentifier)
        } while sequence.more
    }
    
}


// End of File
