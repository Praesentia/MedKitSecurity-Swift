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
 PublicKeyCredentials factory.
 */
public class PublicKeyCredentialsFactory: CredentialsFactory {
    
    // MARK: - Class Properties
    static let shared = PublicKeyCredentialsFactory()
    
    // MARK: - Instantiation
    
    /**
     Create credentials from profile.
     */
    public func instantiate(for identity: Identity, from profile: Any, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    {
        if let profile = profile as? [String : Any], let data = decodeCertificate(profile[KeyCertificate]), let chain = decodeCertificateChain(profile[KeyCertificateChain]) {
            SecurityManagerShared.main.instantiatePublicKeyCredentials(for: identity, from: data, chain: chain, completionHandler: completion)
        }
        else {
            completion(nil, SecurityKitError.failed)
        }
    }
    
    private func decodeCertificate(_ certificate: Any?) -> Data?
    {
        if let string = certificate as? String {
            return Data(base64Encoded: string)
        }
        return nil
    }
    
    private func decodeCertificateChain(_ chain: Any?) -> [Data]?
    {
        if let array = chain as? [String] {
            var certificateChain = [Data]()
        
            for string in array {
                if let data = Data(base64Encoded: string) {
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
