/*
 -----------------------------------------------------------------------------
 This source file is part of MedKitCore.
 
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


import XCTest
import MedKitCore
@testable import MedKitSecurity


class DEREncoderTests: XCTestCase {
    
    let encoder = DEREncoder()
    
    func testObjectIdentifier()
    {
        let oid = encoder.encodeObjectIdentifier(components: [ 2, 5, 4, 3 ])
        
        XCTAssertEqual(oid, [ 0x06, 0x03, 0x55, 0x04, 0x03 ])
    }
    
    func testSequence()
    {
        let sequence = encoder.encodeSequence(bytes: [ 1, 2, 3 ])
        
        XCTAssertEqual(sequence, [ 0x30, 0x03, 0x01, 0x02, 0x03 ])
    }
    
}


// End of File
