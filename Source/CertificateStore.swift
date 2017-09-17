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
 CertificateStore
 */
class CertificateStore {
    
    static let main = CertificateStore()
    
    // MARK: - Private Properties
    private let keychain: Keychain = Keychain.main
    
    // MARK: - Initializers

    /** Initilializer
     */
    init()
    {
    }
    
    // MARK: - Creation
    
    /**
     Create certificate request.
     
     Creates a new CertificateRequestInfo structure.
     
     - Parameters:
         - subject:   X509 subject name.
         - publicKey: Public key.

     - Returns:

     */
    func createCertificationRequest(for subject: X509Name, withPublicKey publicKey: PublicKey) -> PCKS10CertificationRequestInfo
    {
        let subjectPublicKeyInfo = X509SubjectPublicKeyInfo(publicKey: publicKey)
        return PCKS10CertificationRequestInfo(subject: subject, subjectPublicKeyInfo: subjectPublicKeyInfo)
    }
    
    /**
     Create certification request info.
     
     Generates a new key pair and associated CertificateRequestInfo structure.
     
     - Parameters:
         - subject: X509 subject name.
         - keySize: Key size in bits.
     
     - Invariant:
         (error == nil) ⇒ (certificateRequestInfo != nil)
     */
    func createCertificationRequestInfo(for subject: X509Name, keySize: UInt) -> (certificateRequestInfo: PCKS10CertificationRequestInfo?, error: Error?)
    {
        var certificationRequestInfo: PCKS10CertificationRequestInfo?
        
        let (keyPair, error) = KeyStore.main.createKeyPair(for: subject, keySize: keySize)
        if error == nil, let (publicKey, _) = keyPair {
            certificationRequestInfo = createCertificationRequest(for: subject, withPublicKey: publicKey)
        }
        
        return (certificationRequestInfo, error)
    }
    
    /**
     Create self-signed certificate.
     
     Creates a self-signed certificate for subject.
     
     - Parameters:
         - subject:  X509 subject name.
         - keySize:  Key size in bits.
         - validity: X509 validity range.

     - Returns:
         - certificate: A certificate instance.
         - error:       Error
     
     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func createCertificate(for subject: X509Name, keySize: UInt, validity: X509Validity) -> (certificate: Certificate?, error: Error?)
    {
        let algorithm  = X509Algorithm.sha256WithRSAEncryption
        let digestType = algorithm.digest!
        var error      : Error?
        var keyPair    : (PublicKey, PrivateKey)?
        
        (keyPair, error) = KeyStore.main.createKeyPair(for: subject, keySize: keySize)
        
        if error == nil, let (publicKey, privateKey) = keyPair {

            // create basic TBS certificate
            let publicKeyInfo  = X509SubjectPublicKeyInfo(publicKey: publicKey)
            let serialNumber   = Random.bytes(count: 8)
            var tbsCertificate = X509TBSCertificate(serialNumber: serialNumber, algorithm: algorithm, issuer: subject, validity: validity, subject: subject, publicKey: publicKeyInfo)
            
            // add extensions
            let basicConstraints = X509BasicConstraints(ca: true)
            let keyUsage         = X509KeyUsage()
            
            tbsCertificate.basicConstraints = basicConstraints
            tbsCertificate.keyUsage         = keyUsage
            
            // create certificate
            let signature   = privateKey.sign(bytes: tbsCertificate.bytes, using: digestType)
            let certificate = X509Certificate(tbsCertificate: tbsCertificate, algorithm: algorithm, signature: signature)
            
            return importCertificate(certificate)
        }
        
        return (nil, error)
    }
    
    // MARK: - Import
    
    /**
     Import certificate from data.
     
     Imports a certificate into the keychain.

     - Returns:
         - certificate: A certificate instance.
         - error:       Error

     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func importCertificate(from data: Data) -> (certificate: Certificate?, error: Error?)
    {
        if let secCertificate = SecCertificate.create(from: data) {
            let error = keychain.importCertificate(from: secCertificate)
            
            if error == nil {
                return (X509(from: secCertificate), nil)
            }
            
            return (nil, SecurityKitError(from: error))
        }
        
        return (nil, SecurityKitError.invalidData)
    }
    
    /**
     Import X059 certificate.
     
     Imports an X509 certificate into the certificate store.

     - Returns:
         - certificate: A certificate instance.
         - error:       Error

     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func importCertificate(_ certificate: X509Certificate) -> (Certificate?, Error?)
    {
        if let secCertificate = SecCertificate.create(from: certificate.data) {
            let error = keychain.importCertificate(from: secCertificate)
            
            if error == nil {
                return (X509(from: secCertificate), nil)
            }
            
            return (nil, SecurityKitError(from: error))
        }
        
        return (nil, SecurityKitError.invalidData)
    }
    
    /**
     Import certificate.
     
     Imports an ephemeral certificate into the certificate store.

     - Returns:

     */
    func importCertificate(_ certificate: Certificate) -> Error?
    {
        if let x509 = certificate.x509 {
            let (_, error) = importCertificate(x509)
            return error
        }
        
        return SecurityKitError.invalidData
    }
    
    /**
     Import public key certificate from PKCS12 data.
     
     - Parameters:
         - data    : DER encoded PKCS12 data.
         - password: Password used to unlock the PKCS12 data.

     - Returns:
         - certificate:
         - error:
     
     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func importCertificate(from data: Data, with password: String) -> (certificate: Certificate?, error: Error?)
    {
        var certificate: Certificate?
        
        let (identity, error) = keychain.importIdentity(from: data, with: password)
        if error == nil, let identity = identity {
            certificate = X509(from: identity)
        }
        
        return (certificate, SecurityKitError(from: error))
    }
    
    // MARK: - Queries

    /**
     Find root certifcates.

     - Returns:
         - certificates:
         - error:
     
     - Invariant:
         (error == nil) ⇒ (certificates != nil)
     */
    func findRootCertificates() -> (certificates: [Certificate]?, error: Error?)
    {
        let (certificates, error) = keychain.findRootCertificates()
        
        if error == nil, let certificates = certificates {
            return (certificates.map { X509(from: $0) }, nil)
        }
        
        return (nil, SecurityKitError(from: error))
    }
    
    /**
     Get trusted root certificates.

     - Returns:

     */
    func getTrustedCertificates() -> [X509]
    {
        let certificates = keychain.getTrustedCertificates()
        return certificates.map { X509(from: $0) }
    }
    
    /**
     Find certifcates.

     - Returns:
         - certificates:
         - error:
     
     - Invariant:
         (error == nil) ⇒ (certificates != nil)
     */
    func findCertificates(withCommonName commonName: String) -> (certificates: [X509]?, error: Error?)
    {
        let (certificates, error) = keychain.findCertificates(withCommonName: commonName)
        
        if error == nil, let certificates = certificates {
            return (certificates.map { X509(from: $0) }, nil)
        }
        
        return (nil, SecurityKitError(from: error))
    }

    /**
     Find certifcate with fingerprint.

      - Returns:
         - certificate:
         - error:

     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func findCertificate(withFingerprint fingerprint: [UInt8]) -> (certificate: X509?, error: Error?)
    {
        let (certificate, error) = keychain.findCertificate(withFingerprint: fingerprint)

        if error == nil, let certificate = certificate {
            return (X509(from: certificate), nil)
        }

        return (nil, SecurityKitError(from: error))
    }

    // MARK: - Certificate Chains
    
    /**
     Construct certificate chain.
     
     Constructs a certificate chain for the specified certificate.

      - Returns:
         - chain:
         - error:

     - Invariant:
         (error == nil) ⇒ (chain != nil)

     - Remarks:
         This is pretty crude at the moment, it simply picks the longest path.
     */
    func buildCertificateChain(for certificate: Certificate) -> (chain: [X509]?, error: Error?)
    {
        var chain: [X509]?
        var error: Error?
        
        if certificate.selfSigned() {
            chain = []
        }
        else {
            (chain, error) = buildCertificateChain(forIntermediate: certificate)
        }
        
        return (chain, error)
    }
    
    /**
     Instantiate certificate chain from data.

     - Returns:

     */
    func instantiateCertificateChain(from list: [Data]) -> [X509]?
    {
        var chain = [X509]()
        
        for data in list {
            if let certificate = X509(from: data) {
                chain.append(certificate)
            }
            else {
                return nil
            }
        }
        
        return chain
    }
    
    // MARK: - Private
    
    /**
     Load certificate chain.
     
     This method constructs a certificate path for the specified certificate.
     
     - Precondition:
         !certificate.selfSigned

     - Returns:
         - chain:
         - error:
     
     - Invariant:
         (error == nil) ⇒ (chain != nil)
     */
    private func buildCertificateChain(forIntermediate certificate: Certificate) -> (chain: [X509]?, error: Error?)
    {
        var chain : [X509]!
        var error : Error? = SecurityKitError.failed
        
        if let issuer = certificate.x509?.tbsCertificate.issuer {
            var certificates: [X509]?
            
            (certificates, error) = findCertificates(withCommonName: issuer.commonName!.string)
            if error == nil, let certificates = certificates {
                for cert in certificates {
                    if certificate.certifiedBy(cert) {
                        var tail: [X509]?
                        
                        (tail, error) = buildCertificateChain(for: cert)
                        if error == nil, let tail = tail {
                            if chain == nil || tail.count >= chain.count {
                                chain = [cert] + tail
                            }
                        }
                    }
                }
            }
        }
        
        return (chain, error)
    }
    
}


// End of File


