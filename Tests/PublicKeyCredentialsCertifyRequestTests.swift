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


class PublicKeyCredentialsCertificationRequestTests: XCTestCase {
    
    override func setUp()
    {
        Keychain.initialize(keychain: SecKeychain.testKeychain)
    }
    
    func testCertifyRequest()
    {
        let data                 = try! Data(contentsOf: testCAP12URL)
        let (certificate, error) = CertificateStore.main.importCertificate(from: data, with: testCAP12Password)
        
        XCTAssertNil(error)
        XCTAssertNotNil(certificate)
        
        if let certificate = certificate as? X509 {
            let (certificationRequest, error) = certificate.createCertificationRequest()
            
            XCTAssertNil(error)
            XCTAssertNotNil(certificationRequest)
            
            /*
            if error == nil, let certificationRequest = certificationRequest {
                let certificate = credentials.certifyRequest(certificationRequest)
                XCTAssertNotNil(certificate)
            }
             */
        }
    }
    
}


// End of File
