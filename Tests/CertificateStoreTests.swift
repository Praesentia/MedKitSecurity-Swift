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


class CertificateStoreTests: XCTestCase {
    
    let keySize  = UInt(2048)
    let validity = X509Validity(from: Date(), until: OneYear)
    
    override func setUp()
    {
        Keychain.initialize(keychain: SecKeychain.testKeychain)
    }
    
    // MARK: - Create
    
    func testCreateSignSignedCertificate()
    {
        let (certificate, error) = CertificateStore.main.createCertificate(for: testName, keySize: keySize, validity: validity)
        
        XCTAssertNil(error, "\(error)")
        XCTAssertNotNil(certificate)
        
        if error == nil, let certificate = certificate {
            let selfSigned = certificate.selfSigned()
            
            XCTAssertTrue(selfSigned)
            XCTAssertEqual(certificate.publicKey.keySize, keySize)
            XCTAssertNotNil(certificate.privateKey)
        }
    }
    
    // MARK: - Import
    
    func testImportCertificateFromData()
    {
        let data                 = try! Data(contentsOf: testCACerURL)
        let (certificate, error) = CertificateStore.main.importCertificate(from: data)
        
        XCTAssertNil(error, "\(error)")
        XCTAssertNotNil(certificate)
        XCTAssertNotNil(certificate?.x509)
        
        if error == nil, let certificate = certificate {
            let selfSigned = certificate.selfSigned()
            
            XCTAssertTrue(selfSigned)
            XCTAssertEqual(certificate.publicKey.keySize, keySize)
            XCTAssertNil(certificate.privateKey)
            
            let (list, error) = CertificateStore.main.findCertificates(withCommonName: testCAName.commonName!.string)
            if error == nil, let list = list {
                XCTAssertEqual(list.count, 1)
                
                if let certificate = list.first {
                    let selfSigned = certificate.selfSigned()
                    
                    XCTAssertTrue(selfSigned)
                    XCTAssertEqual(certificate.publicKey.keySize, keySize)
                    XCTAssertNil(certificate.privateKey)
                }
            }
        }
    }
    
    // MARK: - Instantiate
    
    func testInstantiateCertificateFromData()
    {
        let data        = try! Data(contentsOf: testCACerURL)
        let x509        = X509Certificate(from: data)!
        let certificate = X509(from: data)
        
        XCTAssertNotNil(certificate)
        XCTAssertNotNil(certificate?.x509)
        
        if let certificate = certificate {
            let selfSigned = certificate.selfSigned()
            
            XCTAssertTrue(selfSigned)
            XCTAssertEqual(certificate.publicKey.keySize, keySize)
            XCTAssertNil(certificate.privateKey)
        }
    }
    
    // MARK: - Certificate chain building.
    
    func testBuildChainForCertificate()
    {
        let caData      = try! Data(contentsOf: testCACerURL)
        let _           = CertificateStore.main.importCertificate(from: caData)
        let cerData     = try! Data(contentsOf: testCerURL)
        let certificate = X509(from: cerData)
        
        XCTAssertNotNil(certificate)
        
        if let certificate = certificate {
            let (chain, error) = CertificateStore.main.buildCertificateChain(for: certificate)
            
            XCTAssertNil(error)
            XCTAssertNotNil(chain)
        }
    }
    
}


// End of File

