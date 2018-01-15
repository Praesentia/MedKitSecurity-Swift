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


import Foundation
@testable import SecurityKitAOS


extension SecKeychain {
    
    /**
     Unit tests run in a simulator with it's own keychain.
     */
    static var testKeychain: SecKeychain? { return instantiateTestKeychain() }
    
    /**
     Just reset the default keychain.
     
     Resets the default keychain by deleting all interesting items.
     */
    private static func instantiateTestKeychain() -> SecKeychain?
    {
        deleteAll(for: kSecClassIdentity)
        deleteAll(for: kSecClassCertificate)
        deleteAll(for: kSecClassKey)
        deleteAll(for: kSecClassGenericPassword)
        deleteAll(for: kSecClassInternetPassword)
        return nil
    }
    
    /**
     Delete all items of type.
     */
    private static func deleteAll(for secClass: CFTypeRef)
    {
        let query: [CFString : Any] = [
            kSecClass : secClass,
        ]
        var status: OSStatus
        
        status = SecItemDelete(query as CFDictionary)
        assert(status == errSecSuccess || status == errSecItemNotFound)
    }
    
}

// End of File
