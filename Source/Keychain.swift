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
import SecurityKit


/**
 Keychain

 The Keychain class implements a facade for the Keychain facility provided by
 iOS and macOS.   The facade is intended to "paper-over" some differences
 between the two operating system and present a more conventional interface for
 Swift development.  It also provides some higher-level functionality for
 support of SecurityKit.
 */
class Keychain {
    
    // MARK: - Class Properties
    static var main: Keychain!
    
    // MARK: - Private Properties
    private let service    : String = "MedKit"
    private let keychain   : SecKeychain?
    private let searchList : [SecKeychain]?
    
    // MARK: - Initialize
    
    /**
     Initialize main keychain instance.

     The keychain paramter may be used to specify an application specific
     keychain (macOS only).
     
     - Parameters:
        - keychain: Keychain instance.

     - Remarks:
         The keychain parameter is ignored on iOS.
     */
    static func initialize(keychain: SecKeychain?)
    {
        main = Keychain(keychain: keychain)
    }
    
    // MARK: - Initializers
    
    /**
     Initialize instance.

     The keychain parameter may be used to specify an application specific
     keychain (macOS only).
     
     - Parameters:
        - keychain: Keychain instance.

     - Remarks:
         The keychain parameter is ignored on iOS.
     */
    init(keychain: SecKeychain?)
    {
        if let keychain = keychain {
            self.keychain   = keychain
            self.searchList = [keychain]
        }
        else {
            self.keychain   = nil
            self.searchList = nil
        }
    }
    
    // MARK: - Public Key

    /**
     Find root certificates.

     - Invariant:
         (error == nil) ⇒ (certificates != nil)
     */
    func findRootCertificates() -> (certificates: [SecCertificate]?, error: Error?)
    {
        var query : [CFString : Any] = [
            kSecClass      : kSecClassCertificate,
            kSecReturnRef  : kCFBooleanTrue,
            kSecMatchLimit : kSecMatchLimitAll
        ]
        
        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }
        
        var result      : AnyObject?
        var status      : OSStatus
        var error       : Error?
        var certificates: [SecCertificate]?
        
        status = SecItemCopyMatching(query as CFDictionary, &result)
        error  = NSError(osstatus: status)
        
        if error == nil {
            certificates = result as! [SecCertificate]?
        }
        
        return (certificates, error)
    }

    /**
     Get trusted root certificates.
     */
    func getTrustedCertificates() -> [SecCertificate]
    {
        var query : [CFString : Any] = [
            kSecClass      : kSecClassCertificate,
            kSecReturnRef  : kCFBooleanTrue,
            kSecMatchLimit : kSecMatchLimitAll
        ]

        if let searchList = self.searchList {
            query[kSecMatchSearchList]  = searchList
            //query[kSecMatchTrustedOnly] = true
        }

        var result: AnyObject?
        var status: OSStatus

        status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let certificates = result as? [SecCertificate] {
            return certificates
        }

        return []
    }

    /**
     Find certificates with common name.

     - Invariant:
         (error == nil) ⇒ (certificates != nil)
     */
    func findCertificates(withCommonName commonName: String) -> (certificates: [SecCertificate]?, error: Error?)
    {
        var query : [CFString : Any] = [
            kSecClass                : kSecClassCertificate,
            kSecReturnRef            : kCFBooleanTrue,
            kSecMatchSubjectContains : commonName,
            kSecMatchLimit           : kSecMatchLimitAll
        ]
        
        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }
        
        var result      : AnyObject?
        var status      : OSStatus
        var error       : Error?
        var certificates: [SecCertificate]?
        
        status = SecItemCopyMatching(query as CFDictionary, &result)
        error  = NSError(osstatus: status)
        
        if error == nil {
            certificates = result as? [SecCertificate]
        }
        
        return (certificates, error)
    }
    /**
     Find certificate with fingerprint.

     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func findCertificate(withFingerprint fingerprint: [UInt8]) -> (certificate: SecCertificate?, error: Error?)
    {
        var query : [CFString : Any] = [
            kSecClass      : kSecClassCertificate,
            kSecReturnRef  : kCFBooleanTrue,
            kSecMatchLimit : kSecMatchLimitAll
        ]

        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }

        var result      : AnyObject?
        var status      : OSStatus
        var error       : Error?
        var certificate : SecCertificate?

        status = SecItemCopyMatching(query as CFDictionary, &result)
        error  = NSError(osstatus: status)

        if error == nil, let array = result as? [SecCertificate] {
            for cert in array {
                if cert.fingerprint == fingerprint {
                    certificate = cert
                    break
                }
            }
        }

        return (certificate, error)
    }

    /**
     Import certificate.
     
     Imports a certificate into the keychain.
     */
    func importCertificate(from certificate: SecCertificate) -> Error?
    {
        var attributes : [CFString : Any] = [
            kSecClass    : kSecClassCertificate,
            kSecValueRef : certificate
        ]
        
        if let keychain = self.keychain {
            attributes[kSecUseKeychain] = keychain
        }
        
        let status = SecItemAdd(attributes as CFDictionary, nil)
        return NSError(osstatus: status)
    }
    
    /**
     Load certificate.
     */
    func loadCertificate(for identity: Identity) -> SecCertificate?
    {
        return SecCertificate.find(keychain, for: identity)
    }
    
    // MARK: - Key Pairs
    
    /**
     Create key pair for identity.

     - Parameters:
         - name   : An X509 name to be assoiciated with the keys.
         - keySize: Key size in bits.
     
     - Invariant:
         (error == nil) ⇒ (keyPair != nil)
     */
    func createKeyPair(for subject: X509Name, keySize: UInt) -> (keyPair: (SecKey, SecKey)?, error: Error?)
    {
        let tagPublic  = self.makePublicKeyTag(for: subject)
        let tagPrivate = self.makePrivateKeyTag(for: subject)
        
        let privateKeyAttr: [CFString : Any] = [
            kSecAttrIsPermanent    : true,
            kSecAttrApplicationTag : tagPrivate
        ]
        
        let publicKeyAttr: [CFString : Any] = [
            kSecAttrIsPermanent    : true,
            kSecAttrApplicationTag : tagPublic
        ]
        
        var parameters: [CFString : Any] = [
            kSecAttrKeyType       : kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits : keySize,
            kSecPrivateKeyAttrs   : privateKeyAttr,
            kSecPublicKeyAttrs    : publicKeyAttr
        ]
        
        if let keychain = self.keychain {
            parameters[kSecUseKeychain] = keychain
        }
        
        var publicKey  : SecKey?
        var privateKey : SecKey?
        var pair       : (SecKey, SecKey)?
        
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        if status == errSecSuccess {
            pair = (publicKey!, privateKey!)
        }
        
        return (pair, NSError(osstatus: status))
    }
    
    /**
     Load private key.
     
     - Parameters:
         - fingerprint:
             A SHA1 hash of the associated public key data.
     
     - Returns:
         ...
     */
    func loadPrivateKey(with fingerprint: Data) -> SecKey?
    {
        var query : [CFString : Any] = [
            kSecClass                : kSecClassKey,
            kSecAttrKeyClass         : kSecAttrKeyClassPrivate,
            kSecAttrKeyType          : kSecAttrKeyTypeRSA,
            kSecAttrApplicationLabel : fingerprint,
            kSecReturnRef            : kCFBooleanTrue,
            kSecMatchLimit           : kSecMatchLimitOne
        ]
        
        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }
        
        var key   : SecKey?
        var result: AnyObject?
        var status: OSStatus
        
        status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            key = result as! SecKey?
        }
        
        return key
    }
    
    /**
     Remove a public/private key pair from the keychain.
     
     - Parameters:
         - name: ...
     */
    func removeKeyPair(for name: X509Name) -> Error?
    {
        let tagPublic  = makePublicKeyTag(for: name)
        let tagPrivate = makePrivateKeyTag(for: name)
        var status     : OSStatus
        
        var queryPublic : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag : tagPublic
        ]
        
        var queryPrivate : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag : tagPrivate
        ]
        
        if let searchList = self.searchList {
            queryPublic[kSecMatchSearchList]  = searchList
            queryPrivate[kSecMatchSearchList] = searchList
        }
        
        status = SecItemDelete(queryPublic as CFDictionary)
        if status == errSecSuccess {
            status = SecItemDelete(queryPrivate as CFDictionary)
        }
        
        return NSError(osstatus: status)
    }
    
    // MARK: - Shared Secret
    
    /**
     Import shared key.
     
     Import a shared secret into the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     destroyed.
     
     - Parameters:
        - identity: The identity to which the shared secret will be associated.
        - secret:   The secret to be interned within the security enclave.

     - Returns:

     */
    func importSharedKey(for identity: Identity, with secret: [UInt8]) -> Error?
    {
        var attributes : [CFString : Any] = [
            kSecClass       : kSecClassGenericPassword,
            kSecAttrService : service,
            kSecAttrAccount : identity.string,
            kSecValueData   : Data(secret)
        ]

        if let keychain = self.keychain {
            attributes[kSecUseKeychain] = keychain
        }
        
        var status: OSStatus
        
        status = SecItemDelete(attributes as CFDictionary)
        if status == errSecSuccess || status == errSecCRLNotFound { // TODO: find correct
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        
        return NSError(osstatus: status)
    }
    
    /**
     Load shared key.
     
     - Invariant:
         (error == nil) ⇒ (secret != nil)
     */
    func loadSharedKey(for identity: Identity) -> (secret: [UInt8]?, error: Error?)
    {
        var query : [CFString : Any] = [
            kSecClass       : kSecClassGenericPassword,
            kSecAttrService : self.service,
            kSecAttrAccount : identity.string,
            kSecReturnData  : kCFBooleanTrue,
            kSecMatchLimit  : kSecMatchLimitOne
        ]
        
        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }
        
        var result : AnyObject?
        var error  : Error?
        var secret : [UInt8]?
        
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        error = NSError(osstatus: status)
        
        if error == nil, let data = result as? Data {
            secret = [UInt8](data)
        }
        
        return (secret, error)
    }
    
    /**
     Remove shared key.
     
     Removes a shared secret from the security enclave that was previously
     interned for identity.
     
     - Parameters:
         - identity:   The identity to which the shared secret will be associated.
         - completion: A completion handler that will be invoked will the result
                       of the operation.
     */
    func removeSharedKey(for identity: Identity) -> Error?
    {
        var query : [CFString : Any] = [
            kSecClass       : kSecClassGenericPassword,
            kSecAttrService : self.service,
            kSecAttrAccount : identity.string
        ]
        
        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }
        
        let status = SecItemDelete(query as CFDictionary)
        return NSError(osstatus: status)
    }
    
    // MARK: - Identity
    
    /**
     Import identity.
     
     Import identity from PKCS12 data.
     
     - Parameters:
         - data:     PKCS12 encoded data.
         - password: Password needed to access PKCS12 data.
     
     - Invariant:
         (error == nil) ⇒ (identity != nil)
     */
    func importIdentity(from data: Data, with password: String) -> (SecIdentity?, Error?)
    {
        var options: [CFString : Any] = [
            kSecImportExportPassphrase: password
        ]
        
        if let keychain = self.keychain {
            options[kSecImportExportKeychain] = keychain
        }
        
        var result  : CFArray?
        var error   : Error?
        var identity: SecIdentity?
        
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &result)
        error = NSError(osstatus: status)
        
        if error == nil, let array = result as? [[CFString : Any]] {
            if array.count > 0 {
                identity = array[0][kSecImportItemIdentity] as! SecIdentity?
                
                #if os(iOS)
                if let identity = identity {
                    error = importIdentity(identity)
                }
                #endif
            }
        }
        
        return (identity, error)
    }
    
    /**
     Import identity.
     
     - Parameters:
         - identity: Identity to be imported into the keychain.
     */
    func importIdentity(_ identity: SecIdentity) -> Error?
    {
        var attributes: [CFString : Any] = [
            kSecValueRef: identity
        ]
        
        if let keychain = self.keychain {
            attributes[kSecUseKeychain] = keychain
        }
        
        let status = SecItemAdd(attributes as CFDictionary, nil)
        return NSError(osstatus: status)
    }
    
    /**
     Instantiate identity.
     
     - Parameters:
         - certificate: Certificate associated with the identity.

     - Invariant:
         (error == nil) ⇒ (identity != nil)
     */
    func instantiateIdentity(with certificate: SecCertificate) -> (identity: SecIdentity?, error: Error?)
    {
        var identity : SecIdentity?
        var error    : Error?
        
        #if os(macOS)
        let status = SecIdentityCreateWithCertificate(searchList as CFTypeRef?, certificate, &identity)
        error = NSError(osstatus: status)
        #else
        error = SecurityKitError.notSupported
        #endif
        
        return (identity, error)
    }
    
    // MARK: - Tags
    
    private func makePublicKeyTag(for name: X509Name) -> Data
    {
        return (name.commonName!.string + ", Public").data(using: .utf8)!
    }
    
    private func makePrivateKeyTag(for name: X509Name) -> Data
    {
        return (name.commonName!.string + ", Private").data(using: .utf8)!
    }
    
}


// End of File
