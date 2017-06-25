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
 X509 Validity
 
 - Requirement: RFC-5280
 */
struct X509Validity: DERCodable {
    
    // MARK: - Properties
    var range: ClosedRange<Date>
    
    // MARK: - Initializers
    
    /**
     Initialize instance from extension.
     */
    init(range: ClosedRange<Date>)
    {
        self.range = range
    }
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    init(decoder: DERDecoder) throws
    {
        let fromDate = try decoder.decodeUTCTime()
        let toDate   = try decoder.decodeUTCTime()
        
        try decoder.assert(fromDate <= toDate)
        try decoder.assertAtEnd()
    
        range = fromDate ... toDate
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        var bytes = [UInt8]()
        
        bytes += encoder.encodeUTCTime(range.lowerBound)
        bytes += encoder.encodeUTCTime(range.upperBound)
        
        return encoder.encodeSequence(bytes: bytes)
    }
    
}


// End of File
