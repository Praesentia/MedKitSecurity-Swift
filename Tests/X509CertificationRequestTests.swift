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
import SecurityKit
@testable import SecurityKitAOS


class X509PCKS10CertificationRequestTests: XCTestCase {
    
    override func setUp()
    {
        Keychain.initialize(keychain: SecKeychain.testKeychain)
    }
    
    func testCreateCertificateRequest()
    {
        let data                 = try! Data(contentsOf: testCAP12URL)
        let (credentials, error) = CredentialsStore.main.importPublicKeyCredentials(from: data, with: testCAP12Password)
        
        XCTAssertNil(error)
        XCTAssertNotNil(credentials)

        if let certificate = credentials?.certificate as? X509 {
            let (certificationRequest, error) = certificate.createCertificationRequest()
            
            XCTAssertNil(error)
            XCTAssertNotNil(certificationRequest)
        }
    }
    
}


// End of File
