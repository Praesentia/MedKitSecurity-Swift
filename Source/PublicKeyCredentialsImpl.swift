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
class PublicKeyCredentialsImpl: PublicKeyCredentials {
    
    // MARK: - Properties
    public var certificate : Certificate
    public var chain       : [Certificate]
    public var identity    : Identity?          { return certificate.identity }
    public var profile     : Any                { return getProfile() }
    public var type        : CredentialsType    { return .publicKey }
    public var validity    : ClosedRange<Date>? { return certificate.validity }

    public var publicKey  : PublicKey           { return certificate.publicKey }
    public var privateKey : PrivateKey?         { return certificate.privateKey }
    
    // MARK: - Internal Properties
    let trust: PublicKeyTrust = PublicKeyTrust.main

    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
        - certificate: Certificate.
        - privateKey:  Private key associated with the certificate.
     */
    init(with certificate: SecCertificate)
    {
        self.certificate = X509(from: certificate)
        self.chain       = []
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - identity: Identity.
     */
    init(with identity: SecIdentity)
    {
        self.certificate = X509(from: identity.certificate!)
        self.chain       = []
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - certificate: X509 certificate.
        - chain:       X509 certificate chain.
        - privateKey:  Private key associated with the certificate.
     */
    init(with certificate: Certificate, chain: [Certificate])
    {
        self.certificate = certificate
        self.chain       = chain
    }
    
    // MARK: - Authentication

    /**
     Verify trust.
     */
    func verifyTrust(completionHandler completion: @escaping (Error?) -> Void)
    {
        trust.verify(certificate: certificate as! X509, with: chain as! [X509], completionHandler: completion)
    }
    
    // MARK: - Certification
    
    /**
     Certify request.
     */
    func certifyRequest(_ certificationRequest: PCKS10CertificationRequest, completionHandler completion: @escaping (X509Certificate?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (certificate, error) = self.certifyRequest(certificationRequest)
            DispatchQueue.main.async { completion(certificate, error) }
        }
    }
    
    /**
     Certify request.
     */
    func certifyRequest(_ certificationRequest: PCKS10CertificationRequest) -> (X509Certificate?, Error?)
    {
        if certificationRequest.verifySignature() {
            let (certificate, error) = certifyRequest(certificationRequestInfo: certificationRequest.certificationRequestInfo)
            return (certificate, error)
        }
        
        return (nil, SecurityKitError.badSignature)
    }
    
    /**
     Certify request.
     */
    public func certifyRequest(certificationRequestInfo: PCKS10CertificationRequestInfo, completionHandler completion: @escaping (X509Certificate?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (certificate, error) = self.certifyRequest(certificationRequestInfo: certificationRequestInfo)
            DispatchQueue.main.async { completion(certificate, error) }
        }
    }
    
    /**
     Certify request.
     */
    func certifyRequest(certificationRequestInfo: PCKS10CertificationRequestInfo) -> (X509Certificate?, Error?)
    {
        if let privateKey = self.privateKey {
            let algorithm  = X509Algorithm.sha256WithRSAEncryption // TODO
            let digestType = algorithm.digest!
            
            if let tbsCertificate = createTBSCertificate(from: certificationRequestInfo) {
                let signature   = privateKey.sign(bytes: tbsCertificate.bytes, using: digestType)
                let certificate = X509Certificate(tbsCertificate: tbsCertificate, algorithm: algorithm, signature: signature)
                
                return (certificate, nil)
            }
        }
        
        return (nil, SecurityKitError.failed)
    }
    
    /**
     Create TBS certificate from certificate request information.
     */
    private func createTBSCertificate(from certificationRequestInfo: PCKS10CertificationRequestInfo) -> X509TBSCertificate?
    {
        var tbsCertificate: X509TBSCertificate!
        
        if let issuer = certificate.x509?.tbsCertificate {
            let from    = Date()
            var expires = from.addingTimeInterval(OneYear)
            if expires > issuer.validity.period.upperBound {
                expires = issuer.validity.period.upperBound
            }
            
            let algorithm      = X509Algorithm.sha256WithRSAEncryption // TODO
            let validity       = X509Validity(period: from...expires)
            let serialNumber   = Random.bytes(count: 8)
            
            tbsCertificate = X509TBSCertificate(serialNumber: serialNumber, algorithm: algorithm,
                                    issuer: issuer.subject, validity: validity,
                                    subject: certificationRequestInfo.subject, publicKey: certificationRequestInfo.subjectPublicKeyInfo)
            
            tbsCertificate.basicConstraints = certificationRequestInfo.basicConstraints
            tbsCertificate.keyUsage         = certificationRequestInfo.keyUsage
        }
        
        return tbsCertificate
    }
    
    // MARK: - Signing
    
    public func sign(bytes: [UInt8], using digestType: DigestType) -> [UInt8]?
    {
        return privateKey?.sign(bytes: bytes, using: digestType)
    }
    
    public func verify(signature: [UInt8], for bytes: [UInt8], using digestType: DigestType) -> Bool
    {
        return publicKey.verify(signature: signature, for: bytes, using: digestType)
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
