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
import MedKitCore


private let Minute = TimeInterval(60)
private let Hour   = TimeInterval(60 * Minute)
private let Day    = TimeInterval(24 * Hour)
private let Year   = TimeInterval(365 * Day)


/**
 Public Key credentials.
 
 - remark
    - Placeholder (not implemented).
 */
class PublicKeyCredentials: Credentials {
    
    // MARK: - Properties
    public var              identity   : Identity?          { return certificate.identity }
    public var              profile    : JSON               { return getProfile() }
    public var              publicKey  : Key                { return certificate.publicKey }
    public private(set) var privateKey : Key?
    public var              type       : CredentialsType    { return .publicKey }
    public var              validity   : ClosedRange<Date>? { return certificate.validity }
    
    // MARK: - Private Properties
    private var certificate : X509    // leaf certificate
    private var chain       : [X509]  // chain

    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    init(with certificate: SecCertificate, privateKey: Key? = nil)
    {
        self.certificate = X509(using: certificate)
        self.chain       = []
        self.privateKey  = privateKey
    }
    
    /**
     Initialize instance.
     */
    init(with identity: SecIdentity)
    {
        self.certificate = X509(using: identity.certificate!)
        self.chain       = []
        self.privateKey  = PrivateKey(identity.privateKey)
    }
    
    /**
     Initialize instance.
     */
    init(with certificate: X509, privateKey: Key? = nil)
    {
        self.certificate = certificate
        self.chain       = []
        self.privateKey  = privateKey
    }
    
    /**
     Initialize instance.
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
        X509Trust.main.verify(leaf: certificate, with: chain, completionHandler: completion)
    }
    
    /**
     Certify request.
     */
    public func certify(certificationRequestInfo: CertificationRequestInfo, completionHandler completion: @escaping (X509Certificate?, Error?) -> Void)
    {
        if let privateKey = self.privateKey {
            
            let from           = Date()
            let to             = from.addingTimeInterval(Year)
            let validity       = from ... to
            let algorithm      = X509Algorithm.sha256WithRSAEncryption
            let issuer         = self.certificate.subject
            let tbsCertificate = X509TBSCertificate(algorithm: algorithm,
                                        issuer: issuer, validity: validity,
                                        subject: certificationRequestInfo.subject, publicKey: certificationRequestInfo.subjectPublicKeyInfo)

            
            let data   = DEREncoder().encode(tbsCertificate)
            let digest = SHA256()
            
            digest.update(bytes: data)
            
            let signature      = privateKey.sign(bytes: digest.final())
            let certificate    = X509Certificate(tbsCertificate: tbsCertificate, algorithm: algorithm, signature: signature)
            
            completion(certificate, nil)
        }
        else {
            completion(nil, MedKitError.failed)
        }
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
        return privateKey?.sign(bytes: bytes)
    }
    
    /**
     Verify signature.
     
     - Parameters:
        - bytes: The bytes that were originally signed.  This will typically be
            a hash value of the actual data.
     */
    public func verify(signature: [UInt8], for bytes: [UInt8]) -> Bool
    {
        return certificate.publicKey.verify(signature: signature, for: bytes)
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
        let profile = JSON()
        
        profile[KeyType]             = type.string
        profile[KeyCertificate]      = certificate.profile
        profile[KeyCertificateChain] = chain.map { $0.profile }
        
        return profile
    }
    
}


// End of File
