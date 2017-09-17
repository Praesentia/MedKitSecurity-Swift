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


class X509Tests: XCTestCase {
    
    func testInitializers()
    {
        let data        = try! Data(contentsOf: testCACerURL)
        let certificate = X509Certificate(from: data)
        
        XCTAssertNotNil(certificate)
    }
    
    func testVerifySignature()
    {
        let caData      = try! Data(contentsOf: testCACerURL)
        let ca          = X509(from: caData)!
        
        let cerData     = try! Data(contentsOf: testCerURL)
        let certificate = X509(from: cerData)!
        let x509        = certificate.x509!
        let digest      = x509.algorithm.digest!
        
        let result = ca.publicKey.verify(signature: x509.signature, for: x509.tbsCertificate.bytes, using: digest)
        
        XCTAssertTrue(result)
    }
    
}


// End of File
