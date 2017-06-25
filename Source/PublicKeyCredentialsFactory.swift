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
 PublicKeyCredentials factory.
 */
public class PublicKeyCredentialsFactory: CredentialsFactory {
    
    // MARK: - Class Properties
    static let shared = PublicKeyCredentialsFactory()
    
    // MARK: - Instantiation
    
    /**
     Create credentials from profile.
     */
    public func instantiate(for identity: Identity, from profile: JSON, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        if let data = decodeCertificate(profile[KeyCertificate]), let chain = decodeCertificateChain(profile[KeyCertificateChain]) {
            SecurityManagerShared.main.instantiatePublicKeyCredentials(for: identity, from: data, chain: chain, completionHandler: completion)
        }
        else {
            completion(nil, MedKitError.failed)
        }
    }
    
    private func decodeCertificate(_ certificate: JSON?) -> Data?
    {
        if let string = certificate?.string {
            return Data(base64Encoded: string)
        }
        return nil
    }
    
    private func decodeCertificateChain(_ chain: JSON?) -> [Data]?
    {
        if let array = chain?.array {
            var certificateChain = [Data]()
        
            for certificate in array {
                if let string = certificate.string, let data = Data(base64Encoded: string) {
                    certificateChain.append(data)
                }
                else {
                    return nil
                }
            }
            
            return certificateChain
        }
        
        return nil
    }
    
}


// End of File
