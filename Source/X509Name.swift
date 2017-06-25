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


struct X509Name: Equatable, DERCodable {
    
    var commonName           : X509String?
    var localityName         : X509String?
    var stateOrProvinceName  : X509String?
    var countryName          : X509String?
    var organizationName     : X509String?
    var organizationUnitName : X509String?
    var emailAddress         : X509String?
    
    // MARK: - Private Properties
    var cache: [UInt8]?
    
    init()
    {
    }
    
    init(from identity: Identity)
    {
        commonName = X509String(string: identity.string)
    }
    
    init(decoder: DERDecoder) throws
    {
        cache = decoder.bytes
        
        repeat {
            let set = try decoder.decoderFromSet()
            
            repeat {
                let attributeTypeValue = try X509AttributeValueType(decoder: try set.decoderFromSequence())
                
                switch attributeTypeValue.oid {
                case X520CommonName :
                    commonName = attributeTypeValue.value
                    
                case X520CountryName :
                    countryName = attributeTypeValue.value
                    
                case X520LocalityName :
                    localityName = attributeTypeValue.value
                    
                case X520StateOrProvinceName :
                    stateOrProvinceName = attributeTypeValue.value
                    
                case X520OrganizationName :
                    organizationName = attributeTypeValue.value
                    
                case X520OrganizationUnitName :
                    organizationUnitName = attributeTypeValue.value
                    
                case PKCS9EmailAddress :
                    emailAddress = attributeTypeValue.value
                    
                default :
                    throw MedKitError.failed
                }
                
            } while set.more
        } while decoder.more
    }
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        if cache != nil {
            return cache!
        }
        
        var bytes = [UInt8]()
        
        if let commonName = commonName {
            bytes += encoder.encode(X509AttributeValueType(oid: X520CommonName, value: commonName))
        }
        
        if let countryName = countryName {
            bytes += encoder.encode(X509AttributeValueType(oid: X520CountryName, value: countryName))
        }
        
        if let localityName = localityName {
            bytes += encoder.encode(X509AttributeValueType(oid: X520LocalityName, value: localityName))
        }
        
        if let stateOrProvinceName = stateOrProvinceName {
            bytes += encoder.encode(X509AttributeValueType(oid: X520StateOrProvinceName, value: stateOrProvinceName))
        }
        
        if let organizationName = organizationName {
            bytes += encoder.encode(X509AttributeValueType(oid: X520OrganizationName, value: organizationName))
        }
        
        if let organizationUnitName = organizationUnitName {
            bytes += encoder.encode(X509AttributeValueType(oid: X520OrganizationUnitName, value: organizationUnitName))
        }
        
        if let emailAddress = emailAddress {
            bytes += encoder.encode(X509AttributeValueType(oid: PKCS9EmailAddress, value: emailAddress))
        }
        
        return encoder.encodeSequence(bytes: bytes)
    }
    
    // MARK: - Private
    
    private static func decodeAttributeTypeValue(decoder: DERDecoder) throws -> ([UInt], String)
    {
        let oid  = try decoder.decodeObjectIdentifier()
        let tag  = try decoder.peekTag()
        var value: String
        
        switch tag {
        case DERCoder.TagPrintableString :
            value = try decoder.decodePrintableString()
            
        case DERCoder.TagUTF8String :
            value = try decoder.decodeUTF8String()
            
        case DERCoder.TagIA5String :
            value = try decoder.decodeIA5String()
            
        default :
            throw MedKitError.failed
        }
        
        try decoder.assertAtEnd()
        return (oid, value)
    }
    
}

// MARK: - Equatable

func ==(lhs: X509Name, rhs: X509Name) -> Bool
{
    return lhs.commonName           == rhs.commonName           &&
           lhs.localityName         == rhs.localityName         &&
           lhs.stateOrProvinceName  == rhs.stateOrProvinceName  &&
           lhs.countryName          == rhs.countryName          &&
           lhs.organizationName     == rhs.organizationName     &&
           lhs.organizationUnitName == rhs.organizationUnitName &&
           lhs.emailAddress         == rhs.emailAddress
}


// End of File
