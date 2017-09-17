/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
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
@testable import SecurityKitAOS


/**
 SHA1 Tests
 */
class SHA1Tests: XCTestCase {
    
    let value = [UInt8](hexString: "da39a3ee5e6b4b0d3255bfef95601890afd80709")!
    
    /**
     - Remark:
        Only confirms that the correct algorithm is being used.
     */
    func testCorrectAlgorithm()
    {
        let digest = SHA1()
        
        digest.update(string: "")
        
        XCTAssert(digest.final() == value)
    }
    
}


// End of File
