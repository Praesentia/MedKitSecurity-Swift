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
 Public Key credentials.
 */
class PublicKeyCredentials: Credentials {
    
    // MARK: - Properties
    public var              identity   : Identity?          { return certificate.identity }
    public var              profile    : Any                { return getProfile() }
    public var              publicKey  : Key                { return certificate.publicKey }
    public private(set) var privateKey : Key?
    public var              type       : CredentialsType    { return .publicKey }
    public var              validity   : ClosedRange<Date>? { return certificate.validity }
    
    // MARK: - Private Properties
    private var certificate : X509    // leaf certificate
    private var chain       : [X509]  // chain
    private let trust       : PublicKeyTrust = PublicKeyTrust.main

    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
        - certificate: Certificate.
        - privateKey:  Private key associated with the certificate.
     */
    init(with certificate: SecCertificate, privateKey: Key? = nil)
    {
        self.certificate = X509(using: certificate)
        self.chain       = []
        self.privateKey  = privateKey
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - identity: Identity.
     */
    init(with identity: SecIdentity)
    {
        self.certificate = X509(using: identity.certificate!)
        self.chain       = []
        self.privateKey  = PrivateKey(identity.privateKey)
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - certificate: X509 certificate.
        - privateKey:  Private key associated with the certificate.
     */
    init(with certificate: X509, privateKey: Key? = nil)
    {
        self.certificate = certificate
        self.chain       = []
        self.privateKey  = privateKey
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - certificate: X509 certificate.
        - chain:       X509 certificate chain.
        - privateKey:  Private key associated with the certificate.
     */
    init(with certificate: X509, chain: [X509], privateKey: Key? = nil)
    {
        self.certificate = certificate
        self.chain       = chain
        self.privateKey  = privateKey
    }
    
    // MARK: - Authentication

    /**
     Verify trust.
     */
    func verifyTrust(completionHandler completion: @escaping (Error?) -> Void)
    {
        trust.verify(certificate: certificate, with: chain, completionHandler: completion)
    }
    
    // MARK: - Signing
    
    /**
     Sign bytes.
     
     - Parameters:
        - bytes: The bytes being signed.  This will typically be a hash value
            of the actual data.
     */
    public func sign(bytes: [UInt8], padding digest: DigestType) -> [UInt8]?
    {
        return privateKey?.sign(bytes: bytes, padding: digest)
    }
    
    /**
     Verify signature.
     
     - Parameters:
        - bytes: The bytes that were originally signed.  This will typically be
            a hash value of the actual data.
     */
    public func verify(signature: [UInt8], padding digest: DigestType, for bytes: [UInt8]) -> Bool
    {
        return certificate.publicKey.verify(signature: signature, padding: digest, for: bytes)
    }
    
    // MARK: - Profile
    
    /**
     Get profile.
     
     Generates a JSON representation of the credentials.
     
     - Returns:
        Returns the generated JSON profile.
     */
    private func getProfile() -> Any
    {
        var profile = [String : Any]()
        
        profile[KeyType]             = type.string
        profile[KeyCertificate]      = certificate.data.base64EncodedString()
        profile[KeyCertificateChain] = chain.map { $0.data.base64EncodedString() }
        
        return profile
    }
    
}


// End of File
