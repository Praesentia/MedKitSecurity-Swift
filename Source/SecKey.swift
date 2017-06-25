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


extension SecKey {
    
    var data: Data? { return SecKeyCopyExternalRepresentation(self, nil) as Data? }
    
    /**
     */
    func sign(bytes: [UInt8]) -> [UInt8]?
    {
        var signature    = [UInt8](repeating: 0, count: SecKeyGetBlockSize(self))
        var signatureLen = signature.count
        
        let status = SecKeyRawSign(self, .PKCS1SHA256, UnsafePointer(bytes), bytes.count, &signature, &signatureLen)
        return (status == errSecSuccess) ? signature : nil
    }
    
    /**
     */
    func verify(signature: [UInt8], for bytes: [UInt8]) -> Bool
    {
        let status = SecKeyRawVerify(self, .PKCS1SHA256, UnsafePointer(bytes), bytes.count, UnsafePointer(signature), signature.count)
        return status == errSecSuccess
    }
    
}


// End of File
