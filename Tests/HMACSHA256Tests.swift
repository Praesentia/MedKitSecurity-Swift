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


import XCTest
@testable import MedKitSecurity


/**
 HMACSHA256 Tests
 
 - See Also:
    RFC 4231
 */
class HMACSHA256Tests: XCTestCase {
    
    let data   = [UInt8](hexString: "4869205468657265")! // "Hi There"
    let key    = [UInt8](hexString: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")!
    let value  = [UInt8](hexString: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")!
    
    /**
     - Remark:
      Only confirms that the correct algorithm is being used.
     */
    func testCorrectAlgorithm()
    {
        let hmac      = HMACSHA256()
        var signature : [UInt8]
        
        signature = hmac.sign(bytes: data, using: key)
        
        XCTAssert(signature == value)
    }
    
}


// End of File
