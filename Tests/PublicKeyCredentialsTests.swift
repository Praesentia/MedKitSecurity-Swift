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


class PublicKeyCredentialsTests: XCTestCase {
    
    let keychain = Keychain(service: SecurityManagerService, keychain: SecKeychain.testKeychain)
    
    override func setUp()
    {
        _ = keychain.removeKeyPair(for: TestIdentity)
    }
    
    override func tearDown()
    {
        _ = keychain.removeKeyPair(for: TestIdentity)
    }
    
    /*
    func testVerifyIdentity()
    {
        var credentials: PublicKeyCredentials!
        let expect     = expectation(description: "GenerateKeyPair")
     
         let expect = expectation(description: "GenerateKeyPair")
         
         keychain.createSelfSignedCertificate(for: TestIdentity) { certificate, error in
         
         XCTAssertNil(error)
         XCTAssertNotNil(certificate)
         
         expect.fulfill()
         }
         
         waitForExpectations(timeout: 60) { error in
         
         }
     
        credentials = generateTestCredentials()
        XCTAssertNotNil(credentials)

        credentials.verifyTrust() { error in
            XCTAssertNil(error)
            expect.fulfill()
        }
         
        waitForExpectations(timeout: 60) { _ in }
    }
    */
    
}


// End of File
