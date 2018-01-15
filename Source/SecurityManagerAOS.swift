/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
 Copyright 2017-2018 Jon Griffeth
 
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


// temporary
private let Minute  = TimeInterval(60)
private let Hour    = TimeInterval(60 * Minute)
private let Day     = TimeInterval(24 * Hour)
private let Year    = TimeInterval(365 * Day)
private let OneYear = Year

/**
 SecurityManager for Apple Operating Systems (AOS)
 
 The SecurityManagerAOS is intended to operate as an adapter.  The
 functionality provided by the class should be limited to that purpose.
 */
class SecurityManagerAOS: SecurityManager {
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    init()
    {
    }
    
    // MARK: - Digest
    
    /**
     Instantiate digest instance.
     
     - Parameters:
        - type: Digest type.
     */
    public func digest(ofType type: DigestType) -> Digest
    {
        return instantiateDigest(ofType: type)
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
        return Random.bytes(count: count)
    }
    
    // MARK: - Generic Credentials
    
    /**
     Create credentials from profile.
     */
    public func decodeCredentials(from decoder: Decoder) throws -> Credentials
    {
        return try CredentialsCoder(from: decoder).credentials
    }
    
    // MARK: - Public Key Certificates
    
    func instantiateCertificate(from certificate: X509Certificate) -> Certificate?
    {
        return X509(from: certificate)
    }
    
    func findCertificates(for identity: Identity, completionHandler completion: @escaping ([Certificate]?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (certificates, error) = CertificateStore.main.findCertificates(withCommonName: identity.string)
            DispatchQueue.main.async { completion(certificates, error) }
        }
    }
    
    func loadChain(for certificate: Certificate, completionHandler completion: @escaping ([Certificate]?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (chain, error) = CertificateStore.main.buildCertificateChain(for: certificate)
            DispatchQueue.main.async { completion(chain, error) }
        }
    }
    
    // MARK: - Public Key Credentials
    
    func findRootCredentials(completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (credentials, error) = CredentialsStore.main.findRootCredentials()
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    func findPublicKeyCredentials(for identity: Identity, completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (credentials, error) = CredentialsStore.main.findPublicKeyCredentials(for: identity)
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }

    func findPublicKeyCredentials(withFingerprint fingerprint: Data, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (credentials, error) = CredentialsStore.main.findPublicKeyCredentials(withFingerprint: fingerprint)
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }

    func findPublicKeyCredentials(withFingerprints fingerprints: [Data], completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            var credentials = [PublicKeyCredentials]()

            for fingerprint in fingerprints {
                let (creds, error) = CredentialsStore.main.findPublicKeyCredentials(withFingerprint: fingerprint)

                if error == nil, let creds = creds {
                    credentials.append(creds)
                }
            }

            DispatchQueue.main.async { completion(credentials, nil) }
        }
    }

    /**
     Create public key credentials.
     
     Create self-signed public key credentials for identity.
     
     - Parameters:
     - identity:
     - completion:
     */
    func createPublicKeyCertificate(for identity: Identity, keySize: UInt, completionHandler completion: @escaping (Certificate?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let subject              = X509Name(from: identity)
            let validity             = X509Validity(from: Date(), until: OneYear)
            let (certificate, error) = CertificateStore.main.createCertificate(for: subject, keySize: keySize, validity: validity)
            DispatchQueue.main.async { completion(certificate, error) }
        }
    }
    
    /**
     Create public key credentials.
     
     Create self-signed public key credentials for identity.
     
     - Parameters:
     - identity:
     - completion:
     */
    func createPublicKeyCertificate(for identity: Identity, keySize: UInt, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (Certificate?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            var certificate              : Certificate?
            var certificationRequestInfo : PCKS10CertificationRequestInfo?
            let issuer                   = issuer as! PublicKeyCredentialsImpl
            let subject                  = X509Name(from: identity)
            var error                    : Error?
            
            (certificationRequestInfo, error) = CertificateStore.main.createCertificationRequestInfo(for: subject, keySize: keySize)
            if error == nil, let certificationRequestInfo = certificationRequestInfo {
                var x509: X509Certificate?
                
                (x509, error) = issuer.certifyRequest(certificationRequestInfo: certificationRequestInfo)
                if error == nil, let x509 = x509 {
                    (certificate, error) = CertificateStore.main.importCertificate(x509)
                }
                
            }
            
            DispatchQueue.main.async { completion(certificate, error) }
        }
    }
    
    /**
     Create public key credentials.
     
     Create self-signed public key credentials for identity.
     
     - Parameters:
        - identity:
        - completion:
     */
    func createPublicKeyCredentials(for identity: Identity, keySize: UInt, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let subject              = X509Name(from: identity)
            let validity             = X509Validity(from: Date(), until: OneYear)

            let (certificate, error) = CertificateStore.main.createCertificate(for: subject, keySize: keySize, validity: validity)
            var credentials          : PublicKeyCredentials?
            
            if error == nil, let certificate = certificate {
                credentials = PublicKeyCredentialsImpl(with: certificate, chain: [])
            }
                
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Create public key credentials.
     
     Create certified public key certificate for identity.
     
     - Parameters:
        - identity:
        - issuer:
     */
    func createPublicKeyCredentials(for identity: Identity, keySize: UInt, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let subject                  = X509Name(from: identity)
            var credentials              : PublicKeyCredentials?
            var certificationRequestInfo : PCKS10CertificationRequestInfo?
            var error                    : Error?

            (certificationRequestInfo, error) = CertificateStore.main.createCertificationRequestInfo(for: subject, keySize: keySize)
            if error == nil, let certificationRequestInfo = certificationRequestInfo {
                let issuer = issuer as! PublicKeyCredentialsImpl
                var x509   : X509Certificate?
                    
                (x509, error) = issuer.certifyRequest(certificationRequestInfo: certificationRequestInfo)
                if error == nil, let x509 = x509 {
                    var certificate : Certificate?
                    
                    (certificate, error) = CertificateStore.main.importCertificate(x509)
                    if error == nil, let certificate = certificate {
                        credentials = PublicKeyCredentialsImpl(with: certificate, chain: [issuer.certificate] + issuer.chain)
                    }
                }
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Create public key credentials.
     
     Create certified public key certificate from existing certificate.
     
     - Parameters:
         - certificate: The certificate used as a template for the new credentials.
         - issuer:
     */
    func createPublicKeyCredentials(from credentials: Credentials, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    {
        let creds                    = credentials as! PublicKeyCredentialsImpl
        let certificate              = creds.certificate
        let subject                  = certificate.x509!.tbsCertificate.subject
        let publicKey                = certificate.publicKey
        let subjectPublicKeyInfo     = X509SubjectPublicKeyInfo(publicKey: publicKey)
        let certificationRequestInfo = PCKS10CertificationRequestInfo(version: 0, subject: subject, subjectPublicKeyInfo: subjectPublicKeyInfo)
        let issuer                   = issuer as! PublicKeyCredentialsImpl
        
        DispatchQueue.module.async {
            var credentials : PublicKeyCredentials?
            var x509        : X509Certificate?
            var error       : Error?
            
            (x509, error) = issuer.certifyRequest(certificationRequestInfo: certificationRequestInfo)
            if error == nil, let x509 = x509 {
                var certificate : Certificate?

                (certificate, error) = CertificateStore.main.importCertificate(x509)
                if error == nil, let certificate = certificate {
                    credentials = PublicKeyCredentialsImpl(with: certificate, chain: [issuer.certificate] + issuer.chain)
                }
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Import public key credentials from X509 data.
     */
    func importPublicKeyCredentials(from data: Data, completionHandler completion: @escaping (Certificate?, Error?) -> Void)
    {
        DispatchQueue.main.async {
            let (certificate, error) = CertificateStore.main.importCertificate(from: data)
            DispatchQueue.main.async { completion(certificate, error) }
        }
    }
    
    /**
     Import public key credentials from pkcs12 data.
     */
    func importPublicKeyCredentials(from data: Data, with password: String, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (credentials, error) = CredentialsStore.main.importPublicKeyCredentials(from: data, with: password)
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    func importPublicKeyCredentials(from certificate: Certificate, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    {
        DispatchQueue.main.async {
            var credentials : PublicKeyCredentials?
            var error       : Error?

            (_, error) = CertificateStore.main.importCertificate(from: certificate.data)
            if error == nil {
                credentials = PublicKeyCredentialsImpl(with: certificate, chain: [])
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    func importPublicKeyCredentials(_ credentials: PublicKeyCredentials, completionHandler completion: @escaping (Error?) -> Void)
    {
        DispatchQueue.main.async {
            var error: Error?
            
            (_, error) = CertificateStore.main.importCertificate(from: credentials.certificate.data)
            
            DispatchQueue.main.async { completion(error) }
        }
    }
    
    /**
     Instantiate public key credentials from X509 data.
     */
    func instantiatePublicKeyCredentials(from data: Data, chain: [Data], completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var credentials : PublicKeyCredentials?
            var error       : Error?
            
            if let certificate = try? X509(from: data), let chain = CertificateStore.main.instantiateCertificateChain(from: chain) {
                credentials = PublicKeyCredentialsImpl(with: certificate, chain: chain)
            }
            else {
                error = SecurityKitError.failed
            }
            
            DispatchQueue.main.async { completion(credentials, error) }
            
        }
    }
    
    public func instantiatePublicKeyCredentials(using certificate: Certificate, chain: [Certificate]) -> PublicKeyCredentials?
    {
        return PublicKeyCredentialsImpl(with: certificate, chain: chain)
    }
    
    // MARK: - Shared Secret
    
    /**
     Import shared secret credentials.
     
     Interns a shared secret within the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     destroyed.
     
     - Parameters:
        - identity:  The identity to which the shared secret will be associated.
        - secret:    The secret to be interned within the security enclave.
        - completion A completion handler that will be invoked with the result
                     of the operation.
     */
    public func importSharedSecretCredentials(for identity: Identity, with secret: Data, using encryptionAlgorithm: SymmetricEncryptionAlgorithm, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (credentials, error) = CredentialsStore.main.importSharedSecretCredentials(for: identity, with: secret, using: encryptionAlgorithm)
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    func loadSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        DispatchQueue.module.async {
            let (credentials, error) = CredentialsStore.main.loadSharedSecretCredentials(for: identity)
            DispatchQueue.main.async { completion(credentials, error) }
        }
    }
    
    /**
     Remove shared secret.
     
     Removes a shared secret from the security enclave for identity.
     
     - Parameters:
        - identity:   The identity to which the shared secret will be associated.
        - completion: A completion handler that will be invoked will the result
                      of the operation.
     */
    public func removeSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)
    {
        DispatchQueue.module.async {
            let error = KeyStore.main.removeSharedSecretCredentials(for: identity)
            DispatchQueue.main.async { completion(error) }
        }
    }
    
}


// End of File
