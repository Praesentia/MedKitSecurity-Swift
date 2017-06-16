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
 Public Key credentials.
 
 - remark
    - Placeholder (not implemented).
 */
class PublicKeyCredentials: Credentials {
    
    // MARK: - Properties
    public var              identity   : Identity?       { return certificate.identity; }
    public var              profile    : JSON            { return getProfile(); }
    public var              publicKey  : Key             { return certificate.publicKey }
    public private(set) var privateKey : Key?
    public var              trusted    : Bool            { return certificate.trusted }
    public var              type       : CredentialsType { return .PublicKey }
    public var              validity   : Range<Date>?    { return nil; } // TODO
    
    // MARK: - Private Properties
    private var certificate : Certificate;

    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    init(with identity: SecIdentity)
    {
        self.certificate = X509(using: identity.certificate!);
        self.privateKey  = PrivateKey(identity.privateKey);
    }
    
    /**
     Initialize instance.
     */
    init(with certificate: Certificate, privateKey: Key? = nil)
    {
        self.certificate = certificate;
        self.privateKey  = privateKey;
    }
    
    // MARK: - Signing
    
    /**
     Sign bytes.
     
     - Parameters:
        - bytes: The bytes being signed.  This will typically be a hash value
            of the actual data.
     */
    public func sign(bytes: [UInt8]) -> [UInt8]?
    {
        return privateKey?.sign(bytes: bytes);
    }
    
    /**
     Verify signature.
     
     - Parameters:
        - bytes: The bytes that were originally signed.  This will typically be
            a hash value of the actual data.
     */
    public func verify(signature: [UInt8], for bytes: [UInt8]) -> Bool
    {
        return certificate.publicKey.verify(signature: signature, for: bytes);
    }
    
    // MARK: - Profile
    
    /**
     Get profile.
     
     Generates a JSON profile representing the credentials.
     
     - Returns:
        Returns the generated JSON profile.
     */
    private func getProfile() -> JSON
    {
        let profile = JSON();
        
        profile[KeyType]             = type.string;
        profile[KeyCertificateChain] = certificate.profile;
        
        return profile;
    }
    
}


// End of File
