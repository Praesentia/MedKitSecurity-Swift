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


/**
 X509 Trust
 
 TODO:
    Implement using SecTrust?
 */
class X509Trust {
    
    static let main = X509Trust()
    
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
     Verify trust.
     
     - Parameters:
        - leaf:       The leaf certificate.
        - chain:      The chain of intermediate authorities.
        - completion: The completion handler.
     */
    func verify(leaf: X509, with chain: [X509], completionHandler completion: @escaping (Error?) -> Void)
    {
        DispatchQueue.module.async {
            
            var certificate = leaf // start from leaf certificate
            var error       : MedKitError?
            
            for authority in chain {
                
                if !authority.publicKey.verify(signature: certificate.signature, using: .sha256, for: certificate.tbsData) {
                    error = .badCredentials
                    break
                }
                
                certificate = authority
            }
            
            if error == nil {
                if !self.trusted(certificate: certificate) {
                    error = .badCredentials
                }
            }
            
            DispatchQueue.main.async { completion(error) }
        }
    }
    
    private func trusted(certificate: X509) -> Bool
    {
        for root in trusted {
            if root.publicKey.verify(signature: certificate.signature, using: .sha256, for: certificate.tbsData) {
                return true
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
