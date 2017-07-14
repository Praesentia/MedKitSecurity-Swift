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
import SecurityKit
@testable import MedKitSecurity


class X509VerificationTests: XCTestCase {
    
    var root: X509!
    var leaf: X509!
    
    override func setUp()
    {
        let rootURL  = Bundle.tests.url(forResource: "TestCA", ofType: "cer")!
        let rootData = try! Data(contentsOf: rootURL)
        let leafURL  = Bundle.tests.url(forResource: "TestUser", ofType: "cer")!
        let leafData = try! Data(contentsOf: leafURL)
        
        root = X509(from: rootData)
        leaf = X509(from: leafData)
    }
    
    func testVerifyRootCertificate()
    {
        XCTAssertTrue(root.verifySelfSigned())
    }
    
    func testVerifyLeafCertificate()
    {
        XCTAssertTrue(root.publicKey.verify(signature: leaf.signature, using: .sha256, for: leaf.tbsData))
    }
    
}


// End of File
