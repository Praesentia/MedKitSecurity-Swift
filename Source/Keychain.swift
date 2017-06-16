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
import MedKitCore;


/**
 Friendlier keychain interface.
 */
class Keychain {
    
    // MARK: - Properties
    public var identities : [Identity] { return loadIdentities(); }
    
    // MARK: - Private Properties
    private let keySize   = 2048;
    private let service   : String;                                  //: Service string.
    private let queue     = DispatchQueue(label: "SecurityManager"); //: Dispatch queue for internal processing.
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
     - service: Identifies the keychain service.
     */
    internal init(service: String)
    {
        self.service = service;
    }
    
    /**
     Load identities.
     */
    private func loadIdentities() -> [Identity]
    {
        let query : [CFString : Any] = [
            kSecClass           : kSecClassGenericPassword,
            kSecAttrService     : service,
            kSecReturnAttributes: kCFBooleanTrue,
            kSecMatchLimit      : 1000 // TODO
        ];
        
        var identities = [Identity]();
        var result     : AnyObject?;
        var status     : OSStatus;
        
        status = SecItemCopyMatching(query as CFDictionary, &result);
        if status == errSecSuccess, let accounts = result as? [AnyObject] {
            for account in accounts {
                if let attributes = account as? [CFString : AnyObject] {
                    if let acct = attributes[kSecAttrAccount] as? String {
                        identities.append(Identity(named: acct, type: .User));
                    }
                }
            }
        }
        
        return identities;
    }
    
    // MARK: - Public Key
    
    /**
     Create self-signed certificate.
     */
    func createCertificate(for identity: Identity, role: SecKeyType) -> (Error?, SecCertificate?)
    {
        let (publicKey, privateKey) = createKeyPair(for: identity, role: role);
        
        if publicKey != nil && privateKey != nil {
            let label   = makeCertificateLabel(for: identity, role: role);
            let name    = X509Name();
            let certGen = X509Encoder();
            
            name.commonName = identity.string;
            
            let bytes = certGen.generateCertificate(issuer: name, subject: name, publicKey: publicKey!, privateKey: privateKey!);
            return internCertificate(with: label, from: bytes);
        }
        
        return (NSError(osstatus: -1), nil);
    }
    
    func createCertificate(from bytes: [UInt8]) -> SecCertificate?
    {
        return createCertificate(from: Data(bytes: bytes));
    }
    
    func createCertificate(from data: Data) -> SecCertificate?
    {
        return SecCertificateCreateWithData(nil, data as CFData)
    }
    
    /**
     Intern certificate.
     
     Interns a certificate into the keychain.
     */
    func internCertificate(with label: String, from bytes: [UInt8]) -> (Error?, SecCertificate?)
    {
        return internCertificate(with: label, from: Data(bytes: bytes));
    }
    
    /**
     Intern certificate.
     
     Interns a certificate into the keychain.
     */
    func internCertificate(with label: String, from data: Data) -> (Error?, SecCertificate?)
    {
        if let certificate = SecCertificateCreateWithData(nil, data as CFData) {
            let error = internCertificate(with: label, from: certificate);
            if error == nil {
                return (nil, certificate);
            }
            return (error, nil);
        }
        return (NSError(osstatus: -1), nil); // for invalid DER format
    }
    
    /**
     Intern certificate.
     
     Interns a certificate into the keychain.
     */
    func internCertificate(with label: String, from certificate: SecCertificate) -> Error?
    {
        let attributes : [CFString : Any] = [
            kSecClass     : kSecClassCertificate,
            kSecAttrLabel : label,
            kSecValueRef  : certificate
        ];
        
        let status = SecItemAdd(attributes as CFDictionary, nil);
        return NSError(osstatus: status);
    }
    
    /**
     Load certificate.
     */
    func loadCertificate(for identity: Identity, role: SecKeyType) -> SecCertificate?
    {
        let label = makeCertificateLabel(for: identity, role: role);
        
        return SecCertificate.find(for: identity, role: role, label: label);
    }
    
    /**
     Create key pair for identity and role.
     */
    func createKeyPair(for identity: Identity, role: SecKeyType) -> (SecKey?, SecKey?)
    {
        let label      = makeLabel(for: identity, role: role);
        let tagPublic  = makePublicKeyTag(for: identity, role: role);
        let tagPrivate = makePrivateKeyTag(for: identity, role: role);
        
        let privateKeyAttr: [CFString : Any] = [
            kSecAttrLabel          : label,     // keychain "name" of private key
            kSecAttrIsPermanent    : true,
            kSecAttrApplicationTag : tagPrivate
        ];
        
        let publicKeyAttr: [CFString : Any] = [
            kSecAttrLabel          : label,     // keychain "name" of public key
            kSecAttrIsPermanent    : true,
            kSecAttrApplicationTag : tagPublic
        ];
        
        let parameters: [CFString : Any] = [
            kSecAttrKeyType       : kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits : keySize,
            kSecPrivateKeyAttrs   : privateKeyAttr,
            kSecPublicKeyAttrs    : publicKeyAttr
        ];
        
        var publicKey  : SecKey?;
        var privateKey : SecKey?;
        
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey);
        if status != errSecSuccess {
            return (nil, nil);
        }
        
        return (publicKey, privateKey);
    }
    
    func removeKeyPair(for identity: Identity, role: SecKeyType) -> Error?
    {
        let tagPublic  = makePublicKeyTag(for: identity, role: role);
        let tagPrivate = makePrivateKeyTag(for: identity, role: role);
        var status     : OSStatus;

        let queryPublic : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag : tagPublic
        ];
        
        let queryPrivate : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag : tagPrivate
        ];
        
        status = SecItemDelete(queryPublic as CFDictionary);
        if status != errSecSuccess {
            return NSError(osstatus: status);
        }
        
        status = SecItemDelete(queryPrivate as CFDictionary);
        return NSError(osstatus: status);
    }
    
    
    /**
     Load public key.
     */
    func loadPublicKey(for identity: Identity, role: SecKeyType) -> SecKey?
    {
        let label = makeLabel(for: identity, role: role);
        let tag   = makePublicKeyTag(for: identity, role: role);
        
        let query : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyClass       : kSecAttrKeyClassPublic,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrLabel          : label,
            kSecAttrApplicationTag : tag,
            kSecReturnRef          : kCFBooleanTrue,
            kSecMatchLimit         : kSecMatchLimitOne
        ];
        
        var result : AnyObject?;
        var key    : SecKey?;
        var status : OSStatus;
        
        status = SecItemCopyMatching(query as CFDictionary, &result);
        if status == errSecSuccess {
            key = result as! SecKey?;
        }
        
        return key;
    }
    
    /**
     Load private key.
     */
    func loadPrivateKey(for identity: Identity, role: SecKeyType) -> SecKey?
    {
        let label = makeLabel(for: identity, role: role);
        let tag   = makePrivateKeyTag(for: identity, role: role);
        
        let query : [CFString : Any] = [
            kSecClass              : kSecClassKey,
            kSecAttrKeyClass       : kSecAttrKeyClassPrivate,
            kSecAttrKeyType        : kSecAttrKeyTypeRSA,
            kSecAttrLabel          : label,
            kSecAttrApplicationTag : tag,
            kSecReturnRef          : kCFBooleanTrue,
            kSecMatchLimit         : kSecMatchLimitOne
        ];
        
        var result : AnyObject?;
        var key    : SecKey?;
        var status : OSStatus;
        
        status = SecItemCopyMatching(query as CFDictionary, &result);
        if status == errSecSuccess {
            key = result as! SecKey?;
        }
        
        return key;
    }
    
    // MARK: - Shared Secret
    
    /**
     Intern shared secret.
     
     Interns a shared secret within the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     destroyed.
     
     - Parameters:
        - secret:    The secret to be interned within the security enclave.
        - identity:  The identity to which the shared secret will be associated.
        - completion A completion handler that will be invoked with the result
                     of the operation.
     */
    func internSecret(_ secret: [UInt8], for identity: Identity) -> Error?
    {
        let attributes : [CFString : Any] = [
            kSecClass       : kSecClassGenericPassword,
            kSecAttrService : self.service,
            kSecAttrAccount : identity.name,
            kSecValueData   : Data(secret)
        ];
        
        var status: OSStatus;
        
        status = SecItemDelete(attributes as CFDictionary);
        
        status = SecItemAdd(attributes as CFDictionary, nil);
        return NSError(osstatus: status);
    }
    
    /**
     Remove shared secret.
     
     Removes a shared secret from the security enclave that was previously
     interned for identity.
     
     - Parameters:
        - identity:   The identity to which the shared secret will be associated.
        - completion: A completion handler that will be invoked will the result
                      of the operation.
     */
    func removeSecret(for identity: Identity) -> Error?
    {
        let query : [CFString : Any] = [
            kSecClass       : kSecClassGenericPassword,
            kSecAttrService : self.service,
            kSecAttrAccount : identity.name
        ];
        
        let status = SecItemDelete(query as CFDictionary);
        return NSError(osstatus: status);
    }
    
    /**
     Load secret.
     */
    func loadSecret(for identity: Identity) -> [UInt8]?
    {
        let query : [CFString : Any] = [
            kSecClass       : kSecClassGenericPassword,
            kSecAttrService : service,
            kSecAttrAccount : identity.name,
            kSecReturnData  : kCFBooleanTrue,
            kSecMatchLimit  : kSecMatchLimitOne
        ];
        
        var result : AnyObject?;
        var secret : [UInt8]?;
        var status : OSStatus;
        
        status = SecItemCopyMatching(query as CFDictionary, &result);
        if status == errSecSuccess, let data = result as? Data {
            secret = [UInt8](data);
        }
        
        return secret;
    }
    
    /**
     Load identity.
     
     Load identity from PKCS12 data.
     
     - Parameters:
        - data:     PKCS12 encoded data.
        - password: Password needed to access PKCS12 data.
     */
    func loadIdentity(from data: Data, with password: String) -> SecIdentity?
    {
        let options: [CFString : Any] = [
            kSecImportExportPassphrase: password
        ];
        var result: CFArray?;
        
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &result);
        if status == errSecSuccess, let array = result as? [[CFString : Any]] {
            if array.count > 0 {
                let identity = array[0][kSecImportItemIdentity] as! SecIdentity;
                return internIdentity(identity) ? identity : nil;
            }
        }
    
        return nil;
    }
    
    // MARK: - Identity
    
    /**
     Load identity.
     
     Load identity from PKCS12 data.
     
     - Parameters:
        - identity: Identity to be interned within the keychain.
     */
    func internIdentity(_ identity: SecIdentity) -> Bool
    {
        let id    = Identity(from: identity.certificate!.commonName!);
        let label = makeCertificateLabel(for: id!, role: SecKeyAuthentication);
        
        let attributes: [CFString : Any] = [
            kSecAttrLabel : label,
            kSecValueRef  : identity
        ];
        
        let status = SecItemAdd(attributes as CFDictionary, nil);
        return status == errSecSuccess;
    }
    
    /**
     Load certificate.
     */
    func loadIdentity(for identity: Identity, role: SecKeyType) -> SecIdentity?
    {
        let label = makeCertificateLabel(for: identity, role: role);
        
        return SecIdentity.find(for: identity, role: role, label: label);
    }
    
    // MARK: - Labels & Tags
    
    private func makeLabel(for identity: Identity, role: UUID) -> String
    {
        return "\(service), \(identity.string), \(role.uuidstring)";
    }
    
    private func makeCertificateLabel(for identity: Identity, role: UUID) -> String
    {
        return makeLabel(for: identity, role: role);
    }
    
    private func makePublicKeyTag(for identity: Identity, role: UUID) -> Data
    {
        let label = makeLabel(for: identity, role: role);
        return (label + ", Public").data(using: .utf8)!;
    }
    
    private func makePrivateKeyTag(for identity: Identity, role: UUID) -> Data
    {
        let label = makeLabel(for: identity, role: role);
        
        return (label + ", Private").data(using: .utf8)!;
    }
    
}


// End of File
