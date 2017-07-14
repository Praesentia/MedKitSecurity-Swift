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


private let Minute  = TimeInterval(60)
private let Hour    = TimeInterval(60 * Minute)
private let Day     = TimeInterval(24 * Hour)
private let Year    = TimeInterval(365 * Day)
private let OneYear = Year


/**
 Keychain interface.
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
     
     - Parameters:
        - service:  Service identifier.
        - keychain: Keychain instance.
     */
    static func initialize(keychain: SecKeychain?)
    {
        main = Keychain(keychain: keychain)
    }
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
        - service: Identifies the keychain service.
        - keychain:
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
    
    func findRootCertificates(completionHandler completion: @escaping ([SecCertificate]?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
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
            
            completion(certificates, error)
        }
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
     Create self-signed certificate.
     
     - Parameters:
        - identity:
        - completion
     */
    func createSelfSignedCertificate(for identity: Identity, completionHandler completion: @escaping (SecCertificate?, Error?) -> Void)
    {
        createKeyPair(for: identity, keySize: 2048) { keyPair, error in
            if error == nil, let (publicKey, privateKey) = keyPair {

                let digestType     = DigestType.sha256
                let name           = X509Name(from: identity)
                let validity       = X509Validity(from: Date(), until: OneYear)
                let algorithm      = X509Algorithm.sha256WithRSAEncryption
                let publicKeyInfo  = X509SubjectPublicKeyInfo(subjectPublicKey: publicKey)
                let serialNumber   = X509TBSCertificate.generateSerialNumber()
                let tbsCertificate = X509TBSCertificate(serialNumber: serialNumber, algorithm: algorithm, issuer: name, validity: validity, subject: name, publicKey: publicKeyInfo)
                
                let tbsData = DEREncoder().encode(tbsCertificate)
                let digest  = SHA256()
                digest.update(bytes: tbsData)
                
                let signature      = privateKey.sign(bytes: digest.final(), padding: digestType.padding)!
                let certificate    = X509Certificate(tbsCertificate: tbsCertificate, algorithm: algorithm, signature: signature)
                let bytes          = DEREncoder().encode(certificate)
                
                self.importCertificate(from: Data(bytes: bytes)) { certificate, error in
                    completion(certificate, error)
                }
            }
            else {
                completion(nil, error)
            }
        }
    }
    
    /**
     Create public key credentials.
     
     - Parameters:
        - identity:
        - issuer:
        - completion:
     */
    func createCertificate(for identity: Identity, issuer: Identity, completionHandler completion: @escaping (SecCertificate?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var certificate: SecCertificate?
            let sync       = Sync2(SecurityKitError.failed)
            
            if let issuer = self.loadIdentity(for: issuer) {

                sync.incr()
                self.createRequest(for: identity, keySize: 2048) { certificationRequestInfo, error in
                    
                    if error == nil, let certificationRequestInfo = certificationRequestInfo {
                        
                        sync.incr()
                        self.certifyRequest(certificationRequestInfo: certificationRequestInfo, authority: issuer) { cert, error in
                            
                            if error == nil, let cert = cert {
                                let data = Data(DEREncoder().encode(cert))
                                
                                sync.incr()
                                self.importCertificate(from: data) { cert, error in
                                    
                                    if error == nil, let cert = cert {
                                        certificate = cert
                                        sync.clear()
                                    }
                                    
                                    sync.decr(error)
                                }
                            }
                            
                            sync.decr(error)
                        }
                    }
                    
                    sync.decr(error)
                }
            }
            
            sync.close() { error in
                completion(certificate, error)
            }
            
        }
    }
    
    /**
     Create certificate request.
     
     Generates a new key pair and associated CertificateRequestInfo structure.
     
     - Parameters:
         - identity:
         - keySize:
     */
    func createRequest(for identity: Identity, keySize: Int, completionHandler completion: @escaping (CertificationRequestInfo?, Error?) -> Void)
    {
        createKeyPair(for: identity, keySize: keySize) { pair, error in
            var certificationRequestInfo: CertificationRequestInfo?
            
            if error == nil, let (publicKey, _) = pair {
                let subject              = X509Name(from: identity)
                let subjectPublicKeyInfo = X509SubjectPublicKeyInfo(subjectPublicKey: publicKey)
                
                certificationRequestInfo = CertificationRequestInfo(subject: subject, subjectPublicKeyInfo: subjectPublicKeyInfo)
            }
            
            completion(certificationRequestInfo, error)
        }
    }
    
    /**
     Certify request.
     */
    public func certifyRequest(certificationRequestInfo: CertificationRequestInfo, authority: SecIdentity, completionHandler completion: @escaping (X509Certificate?, Error?) -> Void)
    {
        if let privateKey = authority.privateKey, let certificateData = authority.certificate?.data {
            
            let issuer    = try! X509Certificate(from: certificateData)
            let algorithm = X509Algorithm.sha256WithRSAEncryption // TODO
            
            let from    = Date()
            var expires = from.addingTimeInterval(OneYear)
            if expires > issuer.tbsCertificate.validity.period.upperBound {
                expires = issuer.tbsCertificate.validity.period.upperBound
            }
            
            let validity       = X509Validity(period: from...expires)
            let serialNumber   = X509TBSCertificate.generateSerialNumber()
            
            let tbsCertificate = X509TBSCertificate(serialNumber: serialNumber, algorithm: algorithm,
                                    issuer: issuer.tbsCertificate.subject, validity: validity,
                                    subject: certificationRequestInfo.subject, publicKey: certificationRequestInfo.subjectPublicKeyInfo)
            
            
            let data       = DEREncoder().encode(tbsCertificate)
            let digestType = DigestType.sha256
            let digest     = SHA256()
            
            digest.update(bytes: data)
            
            let signature      = privateKey.sign(bytes: digest.final(), padding: digestType.padding)!
            let certificate    = X509Certificate(tbsCertificate: tbsCertificate, algorithm: algorithm, signature: signature)
            
            completion(certificate, nil)
        }
        else {
            completion(nil, SecurityKitError.failed)
        }
    }
    
    /**
     Create certificate from data.
     */
    func createCertificate(from data: Data) -> (SecCertificate?, Error?)
    {
        if let certificate = SecCertificateCreateWithData(nil, data as CFData) {
            return (certificate, nil)
        }
        return (nil, NSError(osstatus: -1))
    }
    
    /**
     Import certificate from data.
     
     Imports a certificate into the keychain.
     */
    func importCertificate(from data: Data) -> (SecCertificate?, Error?)
    {
        var certificate: SecCertificate?
        var error      : Error?
        
        (certificate, error) = createCertificate(from: data)
        
        if error == nil {
            error = importCertificate(from: certificate!)
            if error != nil {
                certificate = nil
            }
        }
        
        return (certificate, error)
    }
    
    /**
     Import certificate from data.
     
     Imports a certificate into the keychain.
     */
    func importCertificate(from data: Data, completionHandler completion: @escaping (SecCertificate?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var certificate: SecCertificate?
            var error      : Error?
            
            (certificate, error) = self.createCertificate(from: data)
            if error == nil, let cert = certificate {
                error = self.importCertificate(from: cert)
                if error != nil {
                    certificate = nil
                }
            }
            
            completion(certificate, error)
        }
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
    
    /**
     Create key pair for identity and role.
     */
    func createKeyPair(for identity: Identity, keySize: Int) -> (SecKey?, SecKey?)
    {
        let label      = identity.string
        let tagPublic  = makePublicKeyTag(for: identity)
        let tagPrivate = makePrivateKeyTag(for: identity)
        
        let privateKeyAttr: [CFString : Any] = [
            kSecAttrLabel          : label,     // keychain "name" of private key
            kSecAttrIsPermanent    : true,
            kSecAttrApplicationTag : tagPrivate
        ]

        let publicKeyAttr: [CFString : Any] = [
            kSecAttrLabel          : label,     // keychain "name" of public key
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
        
        var publicKey : SecKey?
        var privateKey: SecKey?
        
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        if status != errSecSuccess {
            return (nil, nil)
        }
        
        return (publicKey, privateKey)
    }
    
    /**
     Create key pair for identity.
     */
    func createKeyPair(for identity: Identity, keySize: Int, completionHandler completion: @escaping ((SecKey, SecKey)?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            let label      = identity.string
            let tagPublic  = self.makePublicKeyTag(for: identity)
            let tagPrivate = self.makePrivateKeyTag(for: identity)
            
            let privateKeyAttr: [CFString : Any] = [
                kSecAttrLabel          : label,     // keychain "name" of private key
                kSecAttrIsPermanent    : true,
                kSecAttrApplicationTag : tagPrivate
            ]
            
            let publicKeyAttr: [CFString : Any] = [
                kSecAttrLabel          : label,     // keychain "name" of public key
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
            
            let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
            if status != errSecSuccess {
                completion(nil, NSError(osstatus: status))
            }
            else {
                completion((publicKey!, privateKey!), nil)
            }
            
        }
    }
    
    /**
     Load public key.
     */
    func loadPublicKey(for identity: Identity) -> SecKey?
    {
        let label = identity.string
        let tag   = makePublicKeyTag(for: identity)
        
        var query : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyClass       : kSecAttrKeyClassPublic,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrLabel          : label,
            kSecAttrApplicationTag : tag,
            kSecReturnRef          : kCFBooleanTrue,
            kSecMatchLimit         : kSecMatchLimitOne
        ]
        
        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }
        
        var result : AnyObject?
        var key    : SecKey?
        var status : OSStatus
        
        status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            key = result as! SecKey?
        }
        
        return key
    }
    
    /**
     Load private key.
     */
    func loadPrivateKey(for identity: Identity) -> SecKey?
    {
        let label = identity.string
        let tag   = makePrivateKeyTag(for: identity)
        
        var query : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyClass       : kSecAttrKeyClassPrivate,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrLabel          : label,
            kSecAttrApplicationTag : tag,
            kSecReturnRef          : kCFBooleanTrue,
            kSecMatchLimit         : kSecMatchLimitOne
        ]
        
        if let searchList = self.searchList {
            query[kSecMatchSearchList] = searchList
        }
        
        var result : AnyObject?
        var key    : SecKey?
        var status : OSStatus
        
        status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            key = result as! SecKey?
        }
        
        return key
    }
    
    func removeKeyPair(for identity: Identity) -> Error?
    {
        let tagPublic  = makePublicKeyTag(for: identity)
        let tagPrivate = makePrivateKeyTag(for: identity)
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
        if status != errSecSuccess {
            return NSError(osstatus: status)
        }
        
        status = SecItemDelete(queryPrivate as CFDictionary)
        return NSError(osstatus: status)
    }
    
    // MARK: - Shared Secret
    
    /**
     Import shared key.
     
     Import a shared secret into the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     destroyed.
     
     - Parameters:
        - identity:  The identity to which the shared secret will be associated.
        - secret:    The secret to be interned within the security enclave.
        - completion A completion handler that will be invoked with the result
                     of the operation.
     */
    func importSharedKey(for identity: Identity, with secret: [UInt8], completionHandler completion: @escaping (Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var attributes : [CFString : Any] = [
                kSecClass       : kSecClassGenericPassword,
                kSecAttrService : self.service,
                kSecAttrAccount : identity.string,
                kSecValueData   : Data(secret)
            ]

            if let keychain = self.keychain {
                attributes[kSecUseKeychain] = keychain
            }
            
            var status: OSStatus
            
            status = SecItemDelete(attributes as CFDictionary)
            
            status = SecItemAdd(attributes as CFDictionary, nil)
            
            completion(NSError(osstatus: status))
            
        }
    }
    
    /**
     Load shared key.
     */
    func loadSharedKey(for identity: Identity, completionHandler completion: @escaping ([UInt8]?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
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
            
            completion(secret, error)
        }
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
    func removeSharedKey(for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var query : [CFString : Any] = [
                kSecClass       : kSecClassGenericPassword,
                kSecAttrService : self.service,
                kSecAttrAccount : identity.string
            ]
            
            if let searchList = self.searchList {
                query[kSecMatchSearchList] = searchList
            }
            
            let status = SecItemDelete(query as CFDictionary)
            
            completion(NSError(osstatus: status))
            
        }
    }
    
    // MARK: - Identity
    
    /**
     Import identity.
     
     Import identity from PKCS12 data.
     
     - Parameters:
         - data:       PKCS12 encoded data.
         - password:   Password needed to access PKCS12 data.
         - completion: Completion handler.
     */
    func importIdentity(from data: Data, with password: String, completionHandler completion: @escaping (SecIdentity?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
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
                        error = self.importIdentity(identity)
                    }
                    #endif
                }
            }
            
            completion(identity, error)
            
        }
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
     Load identity.
     */
    func loadIdentity(for identity: Identity, completionHandler completion: @escaping (SecIdentity?, Error?) -> Void)
    {
        DispatchQueue.module.async {

            var error    : Error?
            let identity = self.loadIdentity(for: identity)
            
            if identity == nil {
                error = SecurityKitError.notFound
            }
            
            completion(identity, error)
            
        }
    }
    
    /**
     Load identity.
     */
    func loadIdentity(for identity: Identity) -> SecIdentity?
    {
        return SecIdentity.find(for: identity, searchList: searchList)
    }
    
    // MARK: - Labels & Tags
    
    private func makePublicKeyTag(for identity: Identity) -> Data
    {
        return (identity.string + ", Public").data(using: .utf8)!
    }
    
    private func makePrivateKeyTag(for identity: Identity) -> Data
    {
        return (identity.string + ", Private").data(using: .utf8)!
    }
    
}


// End of File
