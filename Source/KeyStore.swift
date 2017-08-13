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
 KeyStore
 */
class KeyStore {
    
    static let main = KeyStore()
    
    // MARK: - Private Properties
    private let keychain: Keychain = Keychain.main
    
    // MARK: Initializers
    
    init()
    {
    }
    
    // MARK: - Public Key
    
    /**
     Create public key pair.
     
     - Invariant:
         (error == nil) ⇒ (keyPair != nil)
     */
    func createKeyPair(for name: X509Name, keySize: UInt) -> (keyPair: (PublicKey, PrivateKey)?, error: Error?)
    {
        var keyPair: (PublicKey, PrivateKey)?
        
        let (keys, error) = keychain.createKeyPair(for: name, keySize: keySize)
        if error == nil, let (publicKey, privateKey) = keys {
            keyPair = (PublicKeyRSA(publicKey), PrivateKeyRSA(privateKey))
        }
        
        return (keyPair, SecurityKitError(from: error))
    }
    
    /**
     Load a public key's associated private key.
     
     - Parameters:
         - publicKey:
     
     - Returns:
         ...
     */
    func loadPrivateKey(for publicKey: PublicKey) -> PrivateKey?
    {
        let fingerprint = publicKey.fingerprint
        var privateKey  : PrivateKey?
        
        if let key = keychain.loadPrivateKey(with: Data(fingerprint)) {
            privateKey = PrivateKeyRSA(key)
        }
        return privateKey
    }
    
    // MARK: - Shared Keys
    
    /**
     Import shared secret key.
     
     Interns a shared secret within the security enclave for the specified
     identity.  Any existing key associated with identity will be destroyed.
     
     - Parameters:
         - identity:  The identity to which the shared secret will be associated.
         - secret:    The secret to be interned within the security enclave.

     - Invariant:
         (error == nil) ⇒ (key != nil)
     */
    public func importSharedKey(for identity: Identity, with secret: [UInt8]) -> (SharedKey?, Error?)
    {
        var key: SharedKey?
        
        let error = self.keychain.importSharedKey(for: identity, with: secret)
        if error == nil {
            key = SharedKey(with: secret)
        }
        
        return (key, SecurityKitError(from: error))
    }
    
    /**
     Load shared secret key.
     
     - Parameters:
         - identity:  The identity.
     
     - Invariant:
         (error == nil) ⇒ (key != nil)
     */
    func loadSharedKey(for identity: Identity) -> (SharedKey?, Error?)
    {
        var key: SharedKey?
        
        let (secret, error) = keychain.loadSharedKey(for: identity)
        if error == nil, let secret = secret {
            key = SharedKey(with: secret)
        }
        
        return (key, SecurityKitError(from: error))
    }
    
    /**
     Remove shared secret key.
     
     Removes a shared secret key from the security enclave.
     
     - Parameters:
         - identity: The identity for the shared key.
     */
    public func removeSharedSecretCredentials(for identity: Identity) -> Error?
    {
        let error = keychain.removeSharedKey(for: identity)
        return SecurityKitError(from: error)
    }

}


// End of File

