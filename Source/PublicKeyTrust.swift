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
 Public Key Trust
 
 TODO:
    Implement using SecTrust?
 */
class PublicKeyTrust {
    
    static let main = PublicKeyTrust()
    
    // MARK: - Private Properties
    private lazy var trusted: [X509] = self.getTrustedCertificates()
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    init()
    {
    }
    
    /**
     Verify trust of certificate
     
     - Parameters:
        - certificate: The leaf certificate.
        - chain:       The chain of intermediate authorities.
        - completion:  The completion handler.
     */
    func verify(certificate: X509, with chain: [X509], completionHandler completion: @escaping (Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var error: SecurityKitError?
            
            if !self.verify(certificate: certificate, with: ArraySlice(chain)) {
                error = .badCredentials
            }

            DispatchQueue.main.async { completion(error) }
        }
    }
    
    /**
     Verify trust of certificate.
     
     - Parameters:
        - certificate: The certificate.
        - chain:       The chain of intermediate authorities for the certificate.
     */
    private func verify(certificate: X509, with chain: ArraySlice<X509>) -> Bool
    {
        if let authority = chain.first {
            if verify(certificate: authority, with: chain[1..<chain.count]) {
                return verify(certificate: certificate, issuedBy: authority)
            }
            return false
        }
        
        return verify(certificate: certificate)
    }
    
    /**
     Verify trust of certificate.
     
     - Parameters:
        - certificate: The certificate.
     */
    private func verify(certificate: X509) -> Bool
    {
        // TODO: also check if certificate is already trusted
        // TODO: look up authority instead of using list
        
        for authority in trusted {
            if verify(certificate: certificate, issuedBy: authority) {
                return true
            }
        }
        
        NSLog("Certificate for \"%s\" is not trusted.", certificate.subject.string)
        return false
    }
    
    /**
     Verify certificate issued by authority.
     
     Verify that the certificate has been properly issued by the authority.
     
     - Parameters:
        - certificate: The certificate.
        - authority:   The authority certificate.
     */
    private func verify(certificate: X509, issuedBy authority: X509) -> Bool
    {
        if (certificate.issuer == authority.subject) && (authority.valid(for: certificate.validity)) {
            if let digest = authority.algorithm.digest {
                if authority.publicKey.verify(signature: certificate.signature, using: digest, for: certificate.tbsData) {
                    return true
                }
                else {
                    NSLog("Certificate for \"%s\" has wrong signature.", certificate.subject.string)
                    return false
                }
            }
        }
        
        return false
    }
    
    private func getTrustedCertificates() -> [X509]
    {
        let certificates = Keychain.main.getTrustedCertificates().map { X509(using: $0) }
    
        return certificates.filter { $0.basicConstraints?.cA ?? false }
    }
    
}


// End of File
