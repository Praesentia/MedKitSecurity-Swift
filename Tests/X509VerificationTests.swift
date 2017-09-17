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
import SecurityKit
@testable import SecurityKitAOS


class X509VerificationTests: XCTestCase {
    
    override func setUp()
    {
        Keychain.initialize(keychain: SecKeychain.testKeychain)
    }
    
    func testVerifyRootCertificate()
    {
        let rootData = try! Data(contentsOf: testCACerURL)
        let root     = X509(from: rootData)!

        XCTAssertTrue(root.selfSigned())
    }
    
    func testVerifyLeafCertificate()
    {
        let rootData = try! Data(contentsOf: testCACerURL)
        let root     = X509(from: rootData)!
        let leafData = try! Data(contentsOf: testCerURL)
        let leaf     = X509(from: leafData)!
        
        XCTAssertTrue(root.publicKey.verify(signature: leaf.signature, for: leaf.x509!.tbsCertificate.bytes, using: leaf.algorithm.digest!))
    }
    
}


// End of File
