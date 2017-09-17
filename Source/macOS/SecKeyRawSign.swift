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


func SecKeyRawSign(
        _ key: SecKey,
        _ padding: SecPadding,
        _ dataToSign: UnsafePointer<UInt8>,
        _ dataToSignLen: Int,
        _ sig: UnsafeMutablePointer<UInt8>,
        _ sigLen: UnsafeMutablePointer<Int>) -> OSStatus
{
    var error: Unmanaged<CFError>?
    
    if let transform = SecSignTransformCreate(key, &error) {
        let data = CFDataCreate(nil, dataToSign, dataToSignLen)!
        
        let status = SecKeySetPadding(transform, padding)
        guard(status == errSecSuccess) else { return status }
        
        SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsDigest, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        let result = SecTransformExecute(transform, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        let signature    = result as! CFData
        let signatureLen = CFDataGetLength(signature)
        
        CFDataGetBytes(signature, CFRangeMake(0, signatureLen), sig)
        
        return errSecSuccess
    }

    return errSSLCrypto
}

func SecKeySetPadding(_ transform: SecTransform, _ padding: SecPadding) -> OSStatus
{
    var error: Unmanaged<CFError>?
    
    switch padding {
    case SecPadding.PKCS1MD5 :
        SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestMD5, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestLengthAttribute, 128 as CFNumber, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        return errSecSuccess
    
    case SecPadding.PKCS1SHA1 :
        SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA1, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestLengthAttribute, 160 as CFNumber, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        return errSecSuccess
        
    case SecPadding.PKCS1SHA224 :
        SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA2, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestLengthAttribute, 224 as CFNumber, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        return errSecSuccess
        
    case SecPadding.PKCS1SHA256 :
        SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA2, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestLengthAttribute, 256 as CFNumber, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        return errSecSuccess
        
    case SecPadding.PKCS1SHA384 :
        SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA2, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestLengthAttribute, 384 as CFNumber, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        return errSecSuccess
        
    case SecPadding.PKCS1SHA512 :
        SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA2, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        SecTransformSetAttribute(transform, kSecDigestLengthAttribute, 512 as CFNumber, &error)
        guard(error == nil) else { return errSSLCrypto }
        
        return errSecSuccess
        
    default :
        return errSSLCrypto
    }
}


// End of File
