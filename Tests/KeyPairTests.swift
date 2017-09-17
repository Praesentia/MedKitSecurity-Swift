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


class KeyPairTests: XCTestCase {
    
    let timeout  = TimeInterval(10)
    var bytes    = [UInt8]()
    
    override func setUp()
    {
        let digest = SHA256()
        
        digest.update(bytes: [0, 1, 2, 3, 4, 5, 6, 7])
        bytes = digest.final()
        
        Keychain.initialize(keychain: SecKeychain.testKeychain)
        _ = Keychain.main.removeKeyPair(for: testName)
    }
    
    override func tearDown()
    {
        _ = Keychain.main.removeKeyPair(for: testName)
    }
    
    func testCreateKeyPair()
    {
        /*
        var signature : [UInt8]?
        var verified  : Bool = false
        
        let (keyPair, error) = KeyStore.main.createKeyPair(for: testName, keySize: 2048)

        XCTAssertNil(error)
        XCTAssertNotNil(keyPair)
        
        if error == nil, let (publicKey, privateKey) = keyPair {
            signature = privateKey.sign(bytes: self.bytes, padding: DigestType.sha256.padding)
            XCTAssertNotNil(signature)
            
            verified = publicKey.verify(signature: signature!, for: self.bytes, padding: DigestType.sha256.padding)
            XCTAssertTrue(verified)
            
            reloadPrivateKey = KeyStore.main.loadPrivateKey(for: publicKey)
            XCTAssertNotNil(reloadPrivateKey)
            
            signature = reloadPrivateKey?.sign(bytes: self.bytes, padding: DigestType.sha256.padding)
            XCTAssertNotNil(signature)
        }
         */
    }
    
}


// End of File
