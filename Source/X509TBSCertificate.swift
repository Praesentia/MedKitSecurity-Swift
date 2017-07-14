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
 X509 TBS Certicate
 
 - Requirement: RFC-5280, 4.1
 */
extension X509TBSCertificate: DERCodable {
    
    // MARK: - Private Class Constants
    private static let TagVersion         = DERCoder.makeContextDefinedTag(id: 0, primitive: false)
    private static let TagIssuerUniqueID  = DERCoder.makeContextDefinedTag(id: 1, primitive: false)
    private static let TagSubjectUniqueID = DERCoder.makeContextDefinedTag(id: 2, primitive: false)
    private static let TagExtensions      = DERCoder.makeContextDefinedTag(id: 3, primitive: false)
    
    // MARK: - Initializers
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    init(decoder: DERDecoder) throws
    {
        data            = Data(decoder.bytes)
        version         = try X509TBSCertificate.decodeVersion(decoder: decoder)
        serialNumber    = try decoder.decodeUnsignedInteger()
        algorithm       = try X509Algorithm(decoder: try decoder.decoderFromSequence())
        issuer          = try X509Name(decoder: try decoder.decoderFromSequence())
        validity        = try X509Validity(decoder: try decoder.decoderFromSequence())
        subject         = try X509Name(decoder: try decoder.decoderFromSequence())
        publicKey       = try X509SubjectPublicKeyInfo(decoder: try decoder.decoderFromSequence())
        issuerUniqueID  = try X509TBSCertificate.decodeUniqueIdentifier(decoder: decoder, with: X509TBSCertificate.TagIssuerUniqueID)
        subjectUniqueID = try X509TBSCertificate.decodeUniqueIdentifier(decoder: decoder, with: X509TBSCertificate.TagSubjectUniqueID)
        extensions      = try X509TBSCertificate.decodeExtensions(decoder: decoder)
        
        basicConstraints = nil
        keyUsage         = nil
        extendedKeyUsage = nil
        
        if let extensions = extensions {
            for extn in extensions {
                switch extn.extnID {
                case x509ExtnBasicConstraints :
                    basicConstraints = try X509BasicConstraints(from: extn)
                    
                case x509ExtnKeyUsage :
                    keyUsage = try X509KeyUsage(from: extn)
                    
                case x509ExtnExtendedKeyUsage :
                    extendedKeyUsage = try X509ExtendedKeyUsage(from: extn)
                    
                default :
                    if extn.critical {
                        throw SecurityKitError.failed
                    }
                    break
                }
            }
        }
        
        try decoder.assertAtEnd()
        try verify()
    }
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        var bytes = [UInt8]()
        
        bytes += encoder.encodeContextDefined(id: 0, primitive: false, bytes: encoder.encodeUnsignedInteger(2))
        bytes += encoder.encodeUnsignedInteger(bytes: serialNumber)
        bytes += encoder.encode(algorithm)
        bytes += encoder.encode(issuer)
        bytes += encoder.encode(validity)
        bytes += encoder.encode(subject)
        bytes += encoder.encode(publicKey)
        bytes += encodeExtensions(encoder: encoder)
        
        return encoder.encodeSequence(bytes: bytes)
    }
    
    static func generateSerialNumber() -> [UInt8]
    {
        var serialNumber = [UInt8](repeating: 0, count: 8)
        var result       : Int32
        
        result = SecRandomCopyBytes(kSecRandomDefault, serialNumber.count, &serialNumber)
        if result != errSecSuccess { // TODO: Under what circumstances would this occur?
            fatalError("Unexpected error.")
        }
        
        return serialNumber
    }
    
    private func encodeExtensions(encoder: DEREncoder) -> [UInt8]
    {
        var data = [UInt8]()
        
        //data += encodeExtSubjectKeyIdentifier(encoder: encoder, publicKey)
        //data += encodeExtAuthorityKeyIdentifier(encoder: encoder, publicKey)
        data += encodeExtBasicConstraints(encoder: encoder)
        data += encodeExtKeyUsage(encoder: encoder)
        data  = encoder.encodeSequence(bytes: data)
        
        return encoder.encodeContextDefined(id: 3, primitive: false, bytes: data)!
    }
    
    private func encodeExtKeyUsage(encoder: DEREncoder) -> [UInt8]
    {
        var data     = [UInt8]()
        let valueSeq = encoder.encodeBitString(bytes: [ 0x07, 0xff, 0x80])
        
        data += encoder.encode(x509ExtnKeyUsage)
        data += encoder.encodeBoolean(true) // critical
        data += encoder.encodeOctetString(bytes: valueSeq)
        
        return encoder.encodeSequence(bytes: data)
    }
    
    private func encodeExtBasicConstraints(encoder: DEREncoder) -> [UInt8]
    {
        var data     = [UInt8]()
        let value    = encoder.encodeBoolean(true)
        let valueSeq = encoder.encodeSequence(bytes: value)
        
        data += encoder.encode(x509ExtnBasicConstraints)
        data += encoder.encodeBoolean(true) // critical
        data += encoder.encodeOctetString(bytes: valueSeq)
        
        return encoder.encodeSequence(bytes: data)
    }
    
    /**
     Decode unique identifier.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeUniqueIdentifier(decoder: DERDecoder, with tag: UInt8) throws -> [UInt8]?
    {
        if decoder.peekTag(with: tag) {
            let decoder = try decoder.decoderFromTag(with: tag)
            return try decoder.decodeBitString()
        }
        
        return nil
    }
    
    /**
     Decode extensions.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeExtensions(decoder: DERDecoder) throws -> [X509Extension]?
    {
        if decoder.peekTag(with: TagExtensions) {
            let decoder    = try decoder.decoderFromTag(with: TagExtensions)
            let sequence   = try decoder.decoderFromSequence()
            var extensions = [X509Extension]()
            
            repeat {
                let extnSequence = try sequence.decoderFromSequence()
                extensions.append(try X509Extension(decoder: extnSequence))
            } while sequence.more
            
            try decoder.assertAtEnd()
            return extensions
        }
        
        return nil
    }
    
    /**
     Decode version.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeVersion(decoder: DERDecoder) throws -> [UInt8]?
    {
        if decoder.peekTag(with: TagVersion) {
            let decoder = try decoder.decoderFromTag(with: TagVersion)
            return try decoder.decodeInteger()
        }
        
        return nil
    }
    
    // MARK: -
    
    /**
     Verify certificate.
     */
    private func verify() throws
    {
    }

    
}


// End of File
