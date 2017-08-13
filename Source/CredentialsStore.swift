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
 CredentialsStore
 */
class CredentialsStore {
    
    // MARK: - Properties
    static let main = CredentialsStore()
    
    // MARK: - Private Properties
    private let keychain: Keychain = Keychain.main
    
    // MARK: Initializers
    
    init()
    {
    }
   
    // MARK: - Import
    
    /**
     Import public key credentials from PKCS12 data.
     
     - Parameters:
         - data    : DER encoded PKCS12 data.
         - password: Password used to unlock the PKCS12 data.
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func importPublicKeyCredentials(from data: Data, with password: String) -> (credentials: PublicKeyCredentials?, error: Error?)
    {
        var credentials: PublicKeyCredentials?
        
        let (certificate, error) = CertificateStore.main.importCertificate(from: data, with: password)
        if error == nil, let certificate = certificate {
            credentials = PublicKeyCredentialsImpl(with: certificate, chain: [])
        }
        
        return (credentials, SecurityKitError(from: error))
    }
    
    // MARK: - Queries
    
    /**
     Find root credentials.
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func findRootCredentials() -> (credentials: [PublicKeyCredentials]?, error: Error?)
    {
        var credentials: [PublicKeyCredentials]?
        
        let (certificates, error) = CertificateStore.main.findRootCertificates()
        if error == nil, let certificates = certificates {
            credentials = certificates.map { PublicKeyCredentialsImpl(with: $0, chain: []) }
        }
        
        return (credentials, error)
    }
    
    /**
     Find public key credentials.
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func findPublicKeyCredentials(for identity: Identity) -> (credentials: [PublicKeyCredentials]?, error: Error?)
    {
        var certificates : [X509]?
        var credentials  : [PublicKeyCredentials]!
        var error        : Error?
        
        (certificates, error) = CertificateStore.main.findCertificates(withCommonName: identity.string)
        if error == nil, let certificates = certificates {
            credentials = [PublicKeyCredentials]()
            
            for certificate in certificates {
                let (chain, error) = CertificateStore.main.buildCertificateChain(for: certificate)
                
                if error == nil, let chain = chain {
                    credentials.append(PublicKeyCredentialsImpl(with: certificate, chain: chain))
                }
            }
        }
        
        return (credentials, error)
    }
    
    // MARK: - Shared Secret
    
    /**
     Import shared secret credentials.
     
     Interns a shared secret within the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     destroyed.
     
     - Parameters:
         - identity: The identity to which the shared secret will be associated.
         - secret:   The secret to be interned within the security enclave.
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    public func importSharedSecretCredentials(for identity: Identity, with secret: [UInt8]) -> (Credentials?, Error?)
    {
        var credentials: SharedSecretCredentials?
        
        let (key, error) = KeyStore.main.importSharedKey(for: identity, with: secret)
        if error == nil, let key = key {
            credentials = SharedSecretCredentials(for: identity, with: key)
        }
        
        return (credentials, SecurityKitError(from: error))
    }
    
    /**
     Load shared secret credentials.
     
     - Parameters:
         - identity: The identity.
    
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func loadSharedSecretCredentials(for identity: Identity) -> (Credentials?, Error?)
    {
        var credentials: SharedSecretCredentials?
        
        let (key, error) = KeyStore.main.loadSharedKey(for: identity)
        if error == nil, let key = key {
            credentials = SharedSecretCredentials(for: identity, with: key)
        }
        
        return (credentials, SecurityKitError(from: error))
    }
    
}


// End of File



