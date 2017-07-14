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


class KeyPairTests: XCTestCase {
    
    let keychain = Keychain(keychain: SecKeychain.testKeychain)
    let timeout  = TimeInterval(10)
    var bytes    = [UInt8]()
    
    override func setUp()
    {
        let digest = SHA256()
        
        digest.update(bytes: [0, 1, 2, 3, 4, 5, 6, 7 ])
        bytes = digest.final()
        
        _ = keychain.removeKeyPair(for: TestIdentity)
    }
    
    override func tearDown()
    {
        _ = keychain.removeKeyPair(for: TestIdentity)
    }
    
    func testCreateKeyPair()
    {
        var error      : Error?
        var publicKey  : SecKey?
        var privateKey : SecKey?
        var signature  : [UInt8]?
        var verified   : Bool = false
        
        (publicKey, privateKey) = keychain.createKeyPair(for: TestIdentity, keySize: 2048)
        XCTAssertNotNil(publicKey)
        XCTAssertNotNil(privateKey)
        
        signature = privateKey?.sign(bytes: bytes, padding: DigestType.sha256.padding)
        XCTAssertNotNil(signature)
        
        verified = publicKey?.verify(signature: signature!, padding: DigestType.sha256.padding, for: bytes) ?? false
        XCTAssertTrue(verified)
        
        publicKey = keychain.loadPublicKey(for: TestIdentity)
        XCTAssertNotNil(publicKey)
        
        privateKey = keychain.loadPrivateKey(for: TestIdentity)
        XCTAssertNotNil(privateKey)
        
        signature = privateKey?.sign(bytes: bytes, padding: DigestType.sha256.padding)
        XCTAssertNotNil(signature)
        
        verified = publicKey?.verify(signature: signature!, padding: DigestType.sha256.padding, for: bytes) ?? false
        XCTAssertTrue(verified)
        
        error = keychain.removeKeyPair(for: TestIdentity)
        XCTAssertNil(error)
    }
    
    func testGenerateKeyPair()
    {
        /*
        let expect = expectation(description: "GenerateKeyPair")
        
        keychain.generateKeyPair(for: TestIdentity, role: SecKeyAuthentication) { error in
            XCTAssertNil(error)
            expect.fulfill()
        }
 
        waitForExpectations(timeout: timeout) { error in

        }
         */
    }
    
}


// End of File
