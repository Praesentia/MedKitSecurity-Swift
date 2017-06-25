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
import MedKitCore


extension SecCertificate {
    
    /**
     Load certificate.
     */
    static func find(_ keychain: SecKeychain?, for identity: Identity) -> SecCertificate?
    {
        let query : [CFString : Any] = [
            kSecClass      : kSecClassCertificate,
            kSecAttrLabel  : identity.string,
            kSecReturnRef  : kCFBooleanTrue,
            kSecMatchLimit : kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        var status: OSStatus
        
        status = SecItemCopyMatching(query as CFDictionary, &result)
        if status != errSecSuccess {
            return nil
        }
        
        return result as! SecCertificate?
    }
    
}


// End of File
