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
 SecurityManager for Apple Operating Systems (AOS)
 
 The SecurityManagerAOS is intended to operate as an adapter.  The
 functionality provided within the class should be limited to that purpose.
 */
class SecurityManagerAOS: SecurityManager {
    
    // MARK: - Private Properties
    private let keychain: Keychain = Keychain.main
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
        - service: Identifies the keychain service.
     */
    init()
    {
    }
    
    // MARK: - Digest
    
    /**
     Instantiate digest instance.
     
     - Parameters:
        - type: Digest type.
     */
    public func digest(using type: DigestType) -> Digest
    {
        return instantiateDigest(ofType: type)
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
        return Random.bytes(count: count)
    }
    
    // MARK: - Public Key Certificates
    
    func findRootCertificates(completionHandler completion: @escaping ([Certificate]?, Error?) -> Void)
    {
        keychain.findRootCertificates() { certs, error in
            var certificates: [Certificate]?
            
            if error == nil, let certs = certs {
                certificates = certs.map { X509(using: $0) }
            }
            
            DispatchQueue.main.async { completion(certificates, error) }
        }
    }
    
    // MARK: - Credentials
    
    /**
     Get credentials for identity.
     
     - Parameters:
        - identity: Identity of the principal.
        - type:     The credentials type.
     */
    public func getCredentials(for identity: Identity, using type: CredentialsType, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        switch type {
        case .null :
            DispatchQueue.main.async { completion(NullCredentials.shared, nil) }
            
        case .publicKey :
            loadPublicKeyCredentials(for: identity, completionHandler: completion)
            
        case .sharedSecret :
            loadSharedSecretCredentials(for: identity, completionHandler: completion)
        }
    }
    
    /**
     Create credentials from profile.
     */
    public func instantiateCredentials(for identity: Identity, from profile: Any, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        if let profile = profile as? [String : Any], let string = profile[KeyType] as? String, let type = CredentialsType(string: string) {
            switch type {
            case .null :
                DispatchQueue.main.async { completion(NullCredentials.shared, nil) }
                
            case .publicKey :
                PublicKeyCredentialsFactory.shared.instantiate(for: identity, from: profile, completionHandler: completion)
                
            case .sharedSecret :
                SharedSecretCredentialsFactory.shared.instantiate(for: identity, from: profile, completionHandler: completion)
            }
        }
        else {
            DispatchQueue.main.async { completion(nil, SecurityKitError.failed) }
        }
    }
    
    // MARK: - Public Key Credentials
    
    /**
     Create public key credentials.
     
     Create self-signed public key credentials for identity.
     
     - Parameters:
        - identity:
        - completion:
     */
    func createPublicKeyCredentials(for identity: Identity, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        keychain.createSelfSignedCertificate(for: identity) { certificate, error in
            var credentials: PublicKeyCredentials?
            
            if error == nil, let certificate = certificate {
                credentials = PublicKeyCredentials(with: certificate)
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Create public key credentials.
     
     Create pulbic key credentials for identity, signed by issuer.
     
     - Parameters:
        - identity:
        - issuer:
     */
    func createPublicKeyCredentials(for identity: Identity, issuer: Identity, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        keychain.createCertificate(for: identity, issuer: issuer) { certificate, error in
            var credentials: Credentials?

            if error == nil, let certificate = certificate {
                credentials = PublicKeyCredentials(with: certificate)
            }

            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Import public key credentials from X509 data.
     */
    func importPublicKeyCredentials(from data: Data, completionHandler completion: @escaping (Certificate?, Error?) -> Void)
    {
        keychain.importCertificate(from: data) { cert, error in
            var certificate: Certificate?
            
            if error == nil, let cert = cert {
                certificate = X509(using: cert)
            }
            
            DispatchQueue.main.async { completion(certificate, error) }
        }
    }
    
    /**
     Import public key credentials from pkcs12 data.
     */
    func importPublicKeyCredentials(from data: Data, with password: String, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        keychain.importIdentity(from: data, with: password) { identity, error in
            var credentials: Credentials?
            
            if error == nil, let identity = identity {
                credentials = PublicKeyCredentials(with: identity)
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Instantiate public key credentials from X509 data.
     */
    func instantiatePublicKeyCredentials(for identity: Identity, from data: Data, chain: [Data], completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var credentials : Credentials?
            var error       : Error?
            
            if let certificate = X509(from: data), let chain = self.loadCertificateChain(chain) {
                credentials = PublicKeyCredentials(with: certificate, chain: chain)
            }
            else {
                error = SecurityKitError.failed
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
            
        }
    }
    
    private func loadPublicKeyCredentials(for identity: Identity, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        keychain.loadIdentity(for: identity) { identity, error in
            var credentials: PublicKeyCredentials?
            
            if error == nil, let identity = identity {
                credentials = PublicKeyCredentials(with: identity)
            }

            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    private func loadCertificateChain(_ chain: [Data]) -> [X509]?
    {
        var certificateChain = [X509]()
        
        for data in chain {
            if let certificate = X509(from: data) {
                certificateChain.append(certificate)
            }
            else {
                return nil
            }
        }
        
        return certificateChain
    }
    
    // MARK: - Shared Keys
    
    /**
     Import shared secrt credentials.
     
     Interns a shared secret within the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     destroyed.
     
     - Parameters:
        - identity:  The identity to which the shared secret will be associated.
        - secret:    The secret to be interned within the security enclave.
        - completion A completion handler that will be invoked with the result
                     of the operation.
     */
    public func importSharedSecretCredentials(for identity: Identity, with secret: [UInt8], completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        keychain.importSharedKey(for: identity, with: secret) { error in
            var credentials: Credentials?
            
            if error == nil {
                credentials = SharedSecretCredentials(for: identity, with: SharedKey(with: secret))
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    func loadSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        keychain.loadSharedKey(for: identity) { secret, error in
            var credentials: SharedSecretCredentials?
            
            if error == nil, let secret = secret {
                credentials = SharedSecretCredentials(for: identity, with: SharedKey(with: secret))
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Remove shared secret.
     
     Removes a shared secret from the security enclave for identity.
     
     - Parameters:
        - identity:   The identity to which the shared secret will be associated.
        - completion: A completion handler that will be invoked will the result
                      of the operation.
     */
    public func removeSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)
    {
        keychain.removeSharedKey(for: identity) { error in
            DispatchQueue.main.async { completion(error) }
        }
    }
    
}


// End of File
