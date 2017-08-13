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


import Foundation
@testable import MedKitSecurity


let testKeychainURL      = URL(fileURLWithPath: "test.keychain")
let testKeychainPassword = "test"


extension SecKeychain {
    
    static var testKeychain: SecKeychain? { return instantiateTestKeychain() }
    
    // MARK: Shadowed Properties
    static var _testKeychain: SecKeychain?
    
    class func create(url: URL, password: String) -> SecKeychain?
    {
        var passwordUTF8   = Array(password.utf8)
        let passwordLength = UInt32(passwordUTF8.count)
        var keychain       : SecKeychain?
        
        let status = SecKeychainCreate(url.path, passwordLength, &passwordUTF8, false, nil, &keychain)
        if status != errSecSuccess {
            return nil
        }
        
        return keychain
    }
    
    static func instantiateTestKeychain() -> SecKeychain?
    {
        let fileManager = FileManager.default
        
        do {
            if let keychain = _testKeychain {
                let status = SecKeychainDelete(keychain)
                assert(status == errSecSuccess)
            }
            
            if fileManager.fileExists(atPath: testKeychainURL.path) {
                try fileManager.removeItem(at: testKeychainURL)
            }
            
            if let keychain = SecKeychain.create(url: testKeychainURL, password: testKeychainPassword) {
                _testKeychain = keychain
                return keychain
            }
            
            assert(false)
        }
        catch {
            assert(false)
        }
    }
}

// End of File
