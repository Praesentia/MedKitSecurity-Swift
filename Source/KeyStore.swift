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

 The KeyStore is essentially an adapter to the Keychain facility.
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

     - Parameters:
         - name:    X509 name to be associated with the keys.
         - keySize: Key size in bits.

     - Returns:
         - keyPair:
             The new key pair, if successful.
         - error:
             Nil if successful.  A non-nil value indicates that the operation
             failed, as well as the reason for the failure.

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
     Load private key associated with a public key.
     
     - Parameters:
         - publicKey: The public key.
     
     - Returns:
         Returns a private key.  A return value of nil indicates that the
         private key does not exist within the key store.
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

     - Returns:
         - key:
             A shared secret key, if successful.
         - error:
             Nil if successful.  A non-nil value indicates that the operation
             failed, as well as the reason for the failure.

     - Invariant:
         (error == nil) ⇒ (key != nil)
     */
    public func importSharedKey(for identity: Identity, with secret: [UInt8]) -> (key: SharedKey?, error: Error?)
    {
        var key: SharedKey?
        
        let error = self.keychain.importSharedKey(for: identity, with: secret)
        if error == nil {
            key = SharedKey(with: secret)
        }
        
        return (key, SecurityKitError(from: error))
    }
    
    /**
     Load shared secret key for identity.
     
     - Parameters:
         - identity: The identity associated with the key.

     - Returns:
         - key:
             A shared secret key, if successful.
         - error:
             Nil if successful.  A non-nil value indicates that the operation
             failed, as well as the reason for the failure.

     - Invariant:
         (error == nil) ⇒ (key != nil)
     */
    func loadSharedKey(for identity: Identity) -> (key: SharedKey?, error: Error?)
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
         - identity: The identity associated with the shared key.

     - Returns:
         Returns nil if successful.  A non-nil value indicates that the
         operation failed, as well as the reason for the failure.
     */
    public func removeSharedSecretCredentials(for identity: Identity) -> Error?
    {
        let error = keychain.removeSharedKey(for: identity)
        return SecurityKitError(from: error)
    }

}


// End of File

