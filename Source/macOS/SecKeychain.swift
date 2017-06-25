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


extension SecKeychain {
    
    class func create(url: URL, password: String) -> SecKeychain?
    {
        let pathname       = url.path
        var password       = password
        let passwordLength = UInt32(password.characters.count)
        var keychain       : SecKeychain?
        
        let status = SecKeychainCreate(pathname, passwordLength, &password, false, nil, &keychain)
        
        switch status {
        case errSecSuccess :
            return keychain
            
        default :
            return nil
        }
    }
    
    class func open(from url: URL) -> SecKeychain?
    {
        let pathname = url.path
        var keychain : SecKeychain?
        
        let status = SecKeychainOpen(pathname, &keychain)
        
        if status == errSecSuccess {
            return keychain
        }
        return nil
    }
    
    func unlock(password: String) -> Bool
    {
        var password       = password
        let passwordLength = UInt32(password.characters.count)
        
        let status = SecKeychainUnlock(self, passwordLength, &password, true)
        return status == errSecSuccess
    }

}


// End of File
