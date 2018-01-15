/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
 Copyright 2017-2018 Jon Griffeth
 
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
@testable import SecurityKitAOS


/**
 HMACSHA512 Tests
 
 - See Also:
    RFC 4231
 */
class HMACSHA512Tests: XCTestCase {
    
    let data   = Data(hexString: "4869205468657265")! // "Hi There"
    let key    = Data(hexString: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")!
    let value  = Data(hexString: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")!
    
    /**
     - Remark:
        Only confirms that the correct algorithm is being used.
     */
    func testCorrectAlgorithm()
    {
        let hmac      = HMACSHA512()
        var signature : Data
        
        signature = hmac.sign(data: data, using: key)
        
        XCTAssert(signature == value)
    }
    
}


// End of File
