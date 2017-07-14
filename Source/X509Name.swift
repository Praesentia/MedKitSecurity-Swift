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


extension X509Name: DERCodable {
    
    // MARK: - Initializers
    
    init(decoder: DERDecoder) throws
    {
        commonName             = nil
        countryName            = nil
        localityName           = nil
        stateOrProvinceName    = nil
        organizationName       = nil
        organizationalUnitName = nil
        emailAddress           = nil
        cache                  = decoder.bytes
        
        repeat {
            let set = try decoder.decoderFromSet()
            
            repeat {
                let attributeTypeValue = try X509AttributeValueType(decoder: try set.decoderFromSequence())
                
                switch attributeTypeValue.oid {
                case x520CommonName :
                    commonName = attributeTypeValue.value
                    
                case x520CountryName :
                    countryName = attributeTypeValue.value
                    
                case x520LocalityName :
                    localityName = attributeTypeValue.value
                    
                case x520StateOrProvinceName :
                    stateOrProvinceName = attributeTypeValue.value
                    
                case x520OrganizationName :
                    organizationName = attributeTypeValue.value
                    
                case x520OrganizationalUnitName :
                    organizationalUnitName = attributeTypeValue.value
                    
                case pkcs9EmailAddress :
                    emailAddress = attributeTypeValue.value
                    
                default :
                    throw SecurityKitError.failed
                }
                
            } while set.more
        } while decoder.more
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        if cache != nil {
            return cache!
        }
        
        var bytes = [UInt8]()
        
        if let commonName = commonName {
            bytes += encoder.encode(X509AttributeValueType(oid: x520CommonName, value: commonName))
        }
        
        if let countryName = countryName {
            bytes += encoder.encode(X509AttributeValueType(oid: x520CountryName, value: countryName))
        }
        
        if let localityName = localityName {
            bytes += encoder.encode(X509AttributeValueType(oid: x520LocalityName, value: localityName))
        }
        
        if let stateOrProvinceName = stateOrProvinceName {
            bytes += encoder.encode(X509AttributeValueType(oid: x520StateOrProvinceName, value: stateOrProvinceName))
        }
        
        if let organizationName = organizationName {
            bytes += encoder.encode(X509AttributeValueType(oid: x520OrganizationName, value: organizationName))
        }
        
        if let organizationalUnitName = organizationalUnitName {
            bytes += encoder.encode(X509AttributeValueType(oid: x520OrganizationalUnitName, value: organizationalUnitName))
        }
        
        if let emailAddress = emailAddress {
            bytes += encoder.encode(X509AttributeValueType(oid: pkcs9EmailAddress, value: emailAddress))
        }
        
        return encoder.encodeSequence(bytes: bytes)
    }
    
}


// End of File
