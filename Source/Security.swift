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


import Foundation;


// OS X only.

func SecKeyRawSign(
        _ key: SecKey,
        _ padding: SecPadding,
        _ dataToSign: UnsafePointer<UInt8>,
        _ dataToSignLen: Int,
        _ sig: UnsafeMutablePointer<UInt8>,
        _ sigLen: UnsafeMutablePointer<Int>) -> OSStatus
{
    var error: Unmanaged<CFError>?;
    
    if let signer = SecSignTransformCreate(key, &error) {
        SecTransformSetAttribute(signer, kSecPaddingKey, kSecPaddingPKCS1Key, &error);
        if error != nil {
            return noErr;
        }
        
        SecTransformSetAttribute(signer, kSecDigestTypeAttribute, kSecDigestSHA2,      &error);
        if error != nil {
            return noErr;
        }
     
        return noErr;
    }
    
    /*
    int digestLength = 256;
    CFNumberRef dLen = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &digestLength);
    Boolean set = SecTransformSetAttribute(
        signer,
        kSecDigestLengthAttribute,
        dLen,
        &error);
    CFRelease(dLen);
    */
    
    return noErr; // TODO
}


// End of File
