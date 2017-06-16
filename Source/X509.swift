/*
 -----------------------------------------------------------------------------
 This source file is part of MedKitCore.
 
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


import Foundation;
import MedKitCore;


/**
 */
public class X509: Certificate {
    
    // MARK: - Properties
    public let                   chain     : [Data]
    public private(set) lazy var identity  : Identity?    = self.getIdentity()
    public var                   profile   : JSON         { return getProfile() }
    public private(set) lazy var publicKey : Key          = self.getPublicKey()
    public private(set) lazy var trusted   : Bool         = self.verifyTrust()
    public private(set) lazy var validity  : Range<Date>? = self.certificate.validity
    
    // MARK: Private Properties
    private var certificate : SecCertificate
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
     - chain: The certificate chain.
     */
    public init(using certificate: SecCertificate)
    {
        self.chain       = [];
        self.certificate = certificate;
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - data: X.509 data.
     */
    public convenience init?(from data: Data)
    {
        if let certificate = SecCertificateCreateWithData(nil, data as CFData) {
            self.init(using: certificate);
        }
        else {
            return nil;
        }
    }
    
    // MARK: - Identity
    
    /**
     Verify certificate is for identity.
     
     - Parameters:
        - identity: An identity.
     */
    public func verify(for identity: Identity) -> Bool
    {
        return false;
    }
    
    private func getIdentity() -> Identity?
    {
        if let commonName = certificate.commonName {
            return Identity(from: commonName);
        }
        return nil;
    }
    
    // MARK: - Signature Verification
    
    private func getPublicKey() -> Key
    {
        return PublicKey(SecCertificateCopyPublicKey(certificate)!);
    }

    /**
     Get profile.
     */
    private func verifyTrust() -> Bool
    {
        return true; // TODO
    }
    
    // MARK: - Profile
    
    /**
     Get profile.
     */
    private func getProfile() -> JSON
    {
        let data = SecCertificateCopyData(certificate) as Data;
        return JSON(data.base64EncodedString());
    }
    
}


// End of File
