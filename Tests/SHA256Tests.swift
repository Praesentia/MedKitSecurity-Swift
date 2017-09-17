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
 SHA256 Tests
 */
class SHA256Tests: XCTestCase {
    
    let value = [UInt8](hexString: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")!
    
    /**
     - Remark:
        Only confirms that the correct algorithm is being used.
     */
    func testCorrectAlgorithm()
    {
        let digest = SHA256()
        
        digest.update(string: "")
        
        XCTAssert(digest.final() == value)
    }
    
}


// End of File
