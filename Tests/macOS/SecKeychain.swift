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


import Foundation
@testable import MedKitSecurity


let testKeychainURL      = URL(fileURLWithPath: "test.keychain")
let testKeychainPassword = "test"

func instantiateTestKeychain() -> SecKeychain?
{
    let fileManager = FileManager.default
    
    try? fileManager.removeItem(at: testKeychainURL)
    
    if let keychain = SecKeychain.create(url: testKeychainURL, password: testKeychainPassword) {
        var settings = SecKeychainSettings()
        
        settings.lockInterval    = UInt32.max
        settings.lockOnSleep     = false
        settings.useLockInterval = false
        
        if SecKeychainSetSettings(keychain, &settings) == errSecSuccess {
            if keychain.unlock(password: testKeychainPassword) {
                return keychain
            }
        }
    }

    assert(false)
}

extension SecKeychain {
    
    static var testKeychain: SecKeychain? = instantiateTestKeychain()
    
}

// End of File
