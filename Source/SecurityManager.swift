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

    public var identities : [Identity] { return loadIdentities(); }
    
    // MARK: - Private
    private let service   : String;                                  //: Service string.
    private let serviceTag: Data;                                    //: Byte representation of the service string.
    private let queue     = DispatchQueue(label: "SecurityManager"); //: Dispatch queue for internal processing.
    
    /**
     Initialize instance.
     
     - Parameters:
        - service: Identifies the keychain service.
     */
    internal init(service: String)
    {
        self.service    = service;
        self.serviceTag = service.data(using: .utf8)!;
    }
    
    // MARK: - Credentials
    
    /**
     Get credentials for identity.
     
     - Parameters:
        - identity: Identity of the principal.
        - type:     The credentials type.
     */
    public func getCredentials(for identity: Identity, using type: CredentialsType) -> Credentials?
    {
        var credentials: Credentials?;
        
        switch type {
        case .Null :
            credentials = NullCredentials.shared;
            
        case .SharedSecret :
            credentials = SharedSecret(for: identity);
            
        case .PublicKey :
            break;
        }
        
        return credentials;
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
        if result != 0 { // TODO: Under what circumstances would this occur?
            fatalError("Unexpected error.");
        }
        
        return bytes;
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
    public func internSecret(_ secret: [UInt8], for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)
    {
        queue.async() {
            let query : [CFString : Any] = [
                kSecClass       : kSecClassGenericPassword,
                kSecAttrService : self.service,
                kSecAttrAccount : identity.name,
                kSecValueData   : Data(secret)
            ];
        
            var status: OSStatus;
            
            status = SecItemDelete(query as CFDictionary);
            status = SecItemAdd(query as CFDictionary, nil);
            
            DispatchQueue.main.async() { completion(NSError(osstatus: status)); }
        }
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
    public func removeSecret(for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)
    {
        queue.async() {
            let query : [CFString : Any] = [
                kSecClass       : kSecClassGenericPassword,
                kSecAttrService : self.service,
                kSecAttrAccount : identity.name
            ];
        
            let status = SecItemDelete(query as CFDictionary);
        
            DispatchQueue.main.async() { completion(NSError(osstatus: status)); }
        }
    }

    // MARK: - Public Key
    
    public func getCertificate(for identity: Identity) -> Certificate?
    {
        return nil;
    }
    
    public func verify(certificate: Certificate, for identity: Identity) -> Bool
    {
        return false; // TODO
    }
    
    public func verifySignature(_ signature: [UInt8], for certificate: Certificate, bytes: [UInt8]) -> Bool
    {
        return false; // TODO
    }
    
    // MARK: - Signing and Verification
    
    /**
     Generate signature for identity.
     */
    public func signBytes(_ bytes: [UInt8], for identity: Identity, using type: CredentialsType) -> [UInt8]?
    {
        var signature: [UInt8]?;
        
        switch type {
        case .Null :
            return nil;
            
        case .SharedSecret :
            if let secret = loadSecret(for: identity) {
                signature = signBytes(bytes, using: secret);
            }
            
        case .PublicKey :
            break;
        }
        
        return signature;
    }
    
    /**
     Verify signature for identity.
     
     Verifies the signature using the credentials associated with identity.
     
     - Parameters:
        - signature: The signature to be verified.
        - identity:  The identity used to verify the signature.
        - bytes:     The byte sequence used to generate the signature.
     
     - Returns:
        Returns true if the signature is successfully verified, false otherwise.
     */
    public func verifySignature(_ signature: [UInt8], for identity: Identity, bytes: [UInt8], using type: CredentialsType) -> Bool
    {
        var verified = false;
        
        switch type {
        case .Null :
            return false;
            
        case .SharedSecret :
            if let secret = loadSecret(for: identity) {
                verified = verifySignature(signature, using: secret, bytes: bytes);
            }
            
        case .PublicKey :
            break;
        }
        
        return verified;
    }
    
    /**
     Generate a new key pair for the identity.
     
     - Parameters:
        - identity:
        - completion:
     */
    func generateKeyPair(for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)
    {
        DispatchQueue.main.async() { completion(MedKitError.NotSupported); }
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
        if status == noErr, let accounts = result as? [AnyObject] {
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
    
    /**
     Load secret.
     */
    private func loadSecret(for identity: Identity) -> [UInt8]?
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
        if status == noErr, let data = result as? Data {
            secret = [UInt8](data);
        }
        
        return secret;
    }
    
    /**
     Generate signature using shared secret.
     
     Uses SHA256 HMAC to generate a signature.
     
     - Parameters:
        - bytes:
        - secret:
     */
    private func signBytes(_ bytes: [UInt8], using secret: [UInt8]) -> [UInt8]?
    {
        let hmac = HMAC256();
      
        return hmac.signBytes(bytes: bytes, using: secret);
    }
    
    /**
     Verify signature using shared secret.
     
     - Parameters:
        - signature:
     */
    private func verifySignature(_ signature: [UInt8], using secret: [UInt8], bytes: [UInt8]) -> Bool
    {
        let hmac = HMAC256();
        
        return signature == hmac.signBytes(bytes: bytes, using: secret);
    }
    
}


// End of File
