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


import Foundation


func SecKeyRawVerify(_ key: SecKey,
                     _ padding: SecPadding,
                     _ signedData: UnsafePointer<UInt8>,
                     _ signedDataLen: Int,
                     _ sig: UnsafePointer<UInt8>,
                     _ sigLen: Int) -> OSStatus
{
    var error     : Unmanaged<CFError>?
    let signature = CFDataCreate(nil, sig, sigLen)!
    
    if let transform = SecVerifyTransformCreate(key, signature, &error) {
        let data   = CFDataCreate(nil, signedData, signedDataLen)!
        
        let status = SecKeySetPadding(transform, padding)
        guard(status == errSecSuccess) else { return status }
        
        SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsDigest, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        let result = SecTransformExecute(transform, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        return ((result as! CFBoolean) == kCFBooleanTrue) ? 0 : errSSLCrypto
    }
    
    return errSSLCrypto
}


// End of File
