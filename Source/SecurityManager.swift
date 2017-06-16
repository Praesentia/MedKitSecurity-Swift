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
 Keychain based security manager.
 
 -Remarks:
    Need to scrub sensitive data from memory.
 */
class SecurityManagerKeychain: SecurityManager {

    // MARK: - Properties
    public var identities : [Identity] { return keychain.identities; }
    
    // MARK: - Private Properties
    private let keySize   = 2048;
    private let queue     = DispatchQueue(label: "SecurityManager"); //: Dispatch queue for internal processing.
    private let keychain  : Keychain;
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
        - service: Identifies the keychain service.
     */
    internal init(service: String)
    {
        keychain = Keychain(service: service);
    }
    
    // MARK: - Credentials
    
    /**
     Generate a new certificate for the identity.
     
     - Parameters:
     - identity:
     - completion:
     */
    func createCredentials(for identity: Identity, completionHandler completion: @escaping (Error?, Credentials?) -> Void)
    {
        queue.async() {
            var error       : Error?
            var certificate : SecCertificate?;
            var credentials : Credentials?;
            
            (error, certificate) = self.keychain.createCertificate(for: identity, role: SecKeyAuthentication);
            
            if error == nil {
                credentials = PublicKeyCredentials(with: X509(using: certificate!));
            }
 
            DispatchQueue.main.async() { completion(error, credentials); }
        }
    }
    
    /**
     Generate a new certificate for the identity.
     
     - Parameters:
        - identity:
     */
    func createCredentials(for identity: Identity) -> Credentials?
    {
        var error      : Error?
        var certificate: SecCertificate?;
        
        (error, certificate) = self.keychain.createCertificate(for: identity, role: SecKeyAuthentication);
        
        if error == nil {
            return PublicKeyCredentials(with: X509(using: certificate!));
        }
        return nil;
    }
    
    func createSharedSecretCredentials(for identity: Identity, with secret: [UInt8], completionHandler completion: @escaping (Error?, Credentials?) -> Void)
    {
        internSharedKey(for: identity, with: secret) { error, key in
            var credentials: Credentials?;
            
            if error == nil, let key = key {
                credentials = SharedSecretCredentials(for: identity, with: key);
            }
            
            completion(error, credentials);
        }
    }
    
    /**
     Get credentials for identity.
     
     - Parameters:
     - identity: Identity of the principal.
     - type:     The credentials type.
     */
    public func getCredentials(for identity: Identity, using type: CredentialsType) -> Credentials?
    {
        switch type {
        case .Null :
            return NullCredentials.shared;
            
        case .SharedSecret :
            return loadSharedSecretCredentials(for: identity);
            
        case .PublicKey :
            return loadPublicCredentials(for: identity);
        }
    }
    
    /**
     Create credentials from profile.
     */
    public func getCredentials(for identity: Identity, from profile: JSON) -> Credentials?
    {
        if let string = profile[KeyType].string, let type = CredentialsType(string: string) {
            switch type {
            case .Null :
                return NullCredentials.shared;
                
            case .SharedSecret :
                return SharedSecretCredentialsFactory.shared.instantiate(from: profile, for: identity);
                
            case .PublicKey :
                return PublicKeyCredentialsFactory.shared.instantiate(from: profile, for: identity);
            }
        }
        
        return nil;
    }
    
    func loadSharedSecretCredentials(for identity: Identity) -> Credentials?
    {
        if let key = loadSharedKey(for: identity) {
            return SharedSecretCredentials(for: identity, with: key);
        }
        return nil;
    }
    
    func loadPublicCredentials(for identity: Identity) -> Credentials?
    {
        var credentials: Credentials?;
        
        if let identity = keychain.loadIdentity(for: identity, role: SecKeyAuthentication) {
            credentials = PublicKeyCredentials(with: identity);
        }
        
        return credentials;
    }
    
    func loadPublicCredentials(for identity: Identity, from data: Data) -> Credentials?
    {
        if let certificate = loadCertificate(from: data) {
            return PublicKeyCredentials(with: certificate);
        }
        return nil;
    }
    
    func loadCredentials(fromPKCS12 data: Data, with password: String) -> Credentials?
    {
        if let identity = keychain.loadIdentity(from: data, with: password) {
            let certificate = identity.certificate!;
            let privateKey  = identity.privateKey!;
            
            return PublicKeyCredentials(with: X509(using: certificate), privateKey: PrivateKey(privateKey));
        }
        
        return nil;
    }
    
    // MARK: - Digest
    
    /**
     Get digest instance.
     
     - Parameters:
        - type: Digest type.
     */
    public func digest(using type: DigestType) -> Digest
    {
        switch type {
        case .SHA1 :
            return SHA1();
            
        case .SHA256 :
            return SHA256();
        }
    }
    
    // MARK: - Random
    
    /**
     Generate random bytes.
     
     - Parameters:
        - count: Number of bytes requested.
     
     - Returns:
        Returns a byte array of count bytes.
     */
    public func randomBytes(count: Int) -> [UInt8]
    {
        var bytes  = [UInt8](repeating: 0, count: count);
        var result : Int32;
        
        result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes);
        if result != errSecSuccess { // TODO: Under what circumstances would this occur?
            fatalError("Unexpected error.");
        }
        
        return bytes;
    }
    
    // MARK: - Public Key
    
    /**
     Generate a new key pair for the identity.
     
     - Parameters:
        - identity:
        - completion:
     */
    func generateKeyPair(for identity: Identity, role: SecKeyType, completionHandler completion: @escaping (Error?) -> Void)
    {
        queue.async() {
            //let error = self.keychain.createKeyPair(for: identity, role: role);
            DispatchQueue.main.async() { completion(nil); }
        }
    }
    
    // MARK: - Certificates
    
    /**
     Generate a new certificate for the identity.
     
     - Parameters:
        - identity:
        - completion:
     */
    func generateCertificate(for identity: Identity, role: SecKeyType, completionHandler completion: @escaping (Error?) -> Void)
    {
        queue.async() {
            var error      : Error?;
            var certificate: SecCertificate?;
            
            (error, certificate) = self.keychain.createCertificate(for: identity, role: role);
            
            DispatchQueue.main.async() { completion(error); }
        }
    }
    
    public func getCertificate(for identity: Identity, role: SecKeyType) -> Certificate?
    {
        if let certificate = keychain.loadCertificate(for: identity, role: role) {
            return X509(using: certificate);
        }
        return nil;
    }
    
    private func createCertificate(for identity: Identity) -> SecCertificate?
    {
        return nil;
    }
    
    func loadCertificate(from data: Data) -> Certificate?
    {
        return X509(from: data);
    }
    
    // MARK: - Shared Keys
    
    /**
     Intern shared key.
     
     Interns a shared secret within the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     destroyed.
     
     - Parameters:
        - secret:    The secret to be interned within the security enclave.
        - identity:  The identity to which the shared secret will be associated.
        - completion A completion handler that will be invoked with the result
                     of the operation.
     */
    public func internSharedKey(for identity: Identity, with secret: [UInt8], completionHandler completion: @escaping (Error?, Key?) -> Void)
    {
        queue.async() {
            let error = self.keychain.internSecret(secret, for: identity);
            var key   : Key?;
            
            if error == nil {
                key = SharedKey(with: secret);
            }
            
            DispatchQueue.main.async() { completion(error, key); }
        }
    }
    
    func loadSharedKey(for identity: Identity) -> Key?
    {
        if let secret = keychain.loadSecret(for: identity) {
            return SharedKey(with: secret);
        }
        return nil;
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
    public func removeSharedKey(for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)
    {
        queue.async() {
            let error = self.keychain.removeSecret(for: identity);
            DispatchQueue.main.async() { completion(error); }
        }
    }
    
}


// End of File
