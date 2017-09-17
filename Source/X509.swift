/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
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
 X509 certificate.
 */
class X509: Certificate {

    // MARK: - Properties
    
    /**
     X509 data in DER form.
     */
    public var data: Data { return certificate.data }
    
    /**
     Identity derived from the CN subject field.
     */
    public private(set) lazy var identity: Identity? = self.getIdentity()
    
    /**
     Public key.
     */
    public private(set) lazy var publicKey: PublicKey = PublicKeyRSA(self.certificate.publicKey!)
    
    /**
     Validity date range.
     */
    public var validity: ClosedRange<Date> { return _x509.tbsCertificate.validity.period }
    
    /**
     X509 structure.
     */
    public var x509: X509Certificate? { return _x509 }
    
    // MARK: - Internal Properties
    
    var certificate      : SecCertificate
    var algorithm        : X509Algorithm          { return _x509.algorithm }
    var issuer           : X509Name               { return _x509.tbsCertificate.issuer }
    var signature        : [UInt8]                { return _x509.signature }
    var subject          : X509Name               { return _x509.tbsCertificate.subject }
    
    var basicConstraints : X509BasicConstraints?  { return _x509.tbsCertificate.basicConstraints }
    var keyUsage         : X509KeyUsage?          { return _x509.tbsCertificate.keyUsage }
    var extendedKeyUsage : X509ExtendedKeyUsage?  { return _x509.tbsCertificate.extendedKeyUsage }
    
    // MARK: - Shadowed Properties
    private var _x509: X509Certificate
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
        - certificate: The certificate chain.
     */
    init(from certificate: SecCertificate)
    {
        self.certificate = certificate
        self._x509       = X509Certificate(from: certificate.data)!
    }
    
    /**
     Initialize instance.
     
     - Parameters:
         - identity:
     */
    init(from identity: SecIdentity)
    {
        self.certificate = identity.certificate!
        self._x509       = X509Certificate(from: certificate.data)!
    }
    
    /**
     Initialize instance.
     
     - Parameters:
     */
    convenience init?(from certificate: X509Certificate)
    {
        if let certificate = SecCertificate.create(from: certificate.data) {
            self.init(from: certificate)
        }
        else {
            return nil
        }
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - data: DER encoded X.509 data.
     */
    convenience init?(from data: Data)
    {
        if let certificate = SecCertificate.create(from: data) {
            self.init(from: certificate)
        }
        else {
            return nil
        }
    }
    
    // MARK: -
    
    /**
     Create certification request information.
     */
    private func createCertificationRequestInfo() -> PCKS10CertificationRequestInfo
    {
        let subjectPublicKeyInfo   = X509SubjectPublicKeyInfo(publicKey: publicKey)
        var certificateRequestInfo = PCKS10CertificationRequestInfo(subject: subject, subjectPublicKeyInfo: subjectPublicKeyInfo)
        
        certificateRequestInfo.basicConstraints = basicConstraints
        certificateRequestInfo.keyUsage         = keyUsage
        
        return certificateRequestInfo
    }
    
    /**
     */
    public func createCertificationRequest(completionHandler completion: @escaping (PCKS10CertificationRequest?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (certificationRequest, error) = self.createCertificationRequest()
            
            DispatchQueue.main.async {
                completion(certificationRequest, error)
            }
        }
    }
    
    /**
     */
    func createCertificationRequest() -> (PCKS10CertificationRequest?, Error?)
    {
        let algorithm           = X509Algorithm.sha256WithRSAEncryption // TODO
        let digestType          = algorithm.digest!
        var certificationRequest: PCKS10CertificationRequest?
        var error               : Error? = SecurityKitError.failed
        
        if let privateKey = self.privateKey {
            let certificationRequestInfo = createCertificationRequestInfo()
            let signature                = privateKey.sign(bytes: certificationRequestInfo.bytes, using: digestType)
            
            certificationRequest = PCKS10CertificationRequest(certificationRequestInfo: certificationRequestInfo, signatureAlgorithm: algorithm, signature: signature)
            error                = nil
        }

        return (certificationRequest, error)
    }
    
    public func twin(of certificate: Certificate) -> Bool
    {
        if let certificate = certificate as? X509 {
            if certificate.subject == subject && certificate.publicKey.fingerprint == publicKey.fingerprint {
                return true
            }
        }
        
        return false
    }
    
    func selfSigned() -> Bool
    {
        return certifiedBy(self)
    }
    
    public func certifiedBy(_ authority: Certificate) -> Bool
    {
        if let authority = authority as? X509, authority.subject == issuer {
            if let digest = algorithm.digest {
                if authority.publicKey.verify(signature: signature, for: _x509.tbsCertificate.bytes, using: digest) {
                    return true
                }
            }
        }
        
        return false
    }
    
    // MARK: - Private
    
    private func getIdentity() -> Identity?
    {
        if let commonName = certificate.commonName {
            return Identity(from: commonName)
        }
        return nil
    }
    
    private func decode() -> X509Certificate?
    {
        return X509Certificate(from: data)
    }
    
}


// End of File
