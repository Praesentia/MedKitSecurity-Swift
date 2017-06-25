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


import Foundation
import MedKitCore


/**
 X509 certificate.
 */
public class X509: Certificate {
    
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
     JSON profile.
     */
    public var profile: JSON { return getProfile() }
    
    /**
     Public key.
     */
    public private(set) lazy var publicKey: Key = PublicKey(self.certificate.publicKey!)
    
    /**
     Validity date range.
     */
    public var validity: ClosedRange<Date> { return decoded.tbsCertificate.validity.range }
    
    // MARK: - Internal Properties
    
    var certificate      : SecCertificate
    
    var tbsData          : Data                   { return decoded.tbsCertificate.cache }
    var algorithm        : X509Algorithm          { return decoded.algorithm }
    var issuer           : X509Name               { return decoded.tbsCertificate.issuer }
    var signature        : [UInt8]                { return decoded.signature }
    var subject          : X509Name               { return decoded.tbsCertificate.subject }

    var basicConstraints : X509BasicConstraints?  { return decoded.tbsCertificate.basicConstraints }
    var keyUsage         : X509KeyUsage?          { return decoded.tbsCertificate.keyUsage }
    var extendedKeyUsage : X509ExtendedKeyUsage?  { return decoded.tbsCertificate.extendedKeyUsage }
    
    // MARK: - Private Properties
    private var decoded: X509Certificate
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     - Parameters:
        - certificate: The certificate chain.
     */
    public init(using certificate: SecCertificate)
    {
        self.certificate = certificate
        self.decoded     = try! X509Certificate(from: certificate.data)
    }
    
    /**
     Initialize instance.
     
     - Parameters:
        - data: X.509 data.
     */
    public convenience init?(from data: Data)
    {
        if let certificate = SecCertificateCreateWithData(nil, data as CFData) {
            self.init(using: certificate)
        }
        else {
            return nil
        }
    }
    
    func verifySelfSigned() -> Bool
    {
        return publicKey.verify(signature: signature, using: .sha256, for: tbsData)
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
        return try? X509Certificate(from: data)
    }
    
    /**
     Get profile.
     */
    private func getProfile() -> JSON
    {
        return JSON(certificate.data.base64EncodedString())
    }
    
}


// End of File
