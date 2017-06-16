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


private let Minute = TimeInterval(60);
private let Hour   = TimeInterval(60 * Minute);
private let Day    = TimeInterval(24 * Hour);
private let Year   = TimeInterval(365 * Day);


/**
 Generate certificate.
 
 - Requirements: RFC-5280
 */
class X509Encoder {
    
    // MARK: Private Constants
    private let Version: [UInt8] = [ 0x02 ]; // version 3
    
    // MARK: - Private
    private let encoder = DER();
    
    // MARK: - Initializers
    
    init()
    {
    }
    
    // MARK: -
    
    func generateCertificate(issuer: X509Name, subject: X509Name, publicKey: SecKey, privateKey: SecKey) -> [UInt8]
    {
        let serialNumber   = generateSerialNumber();
        let tbsCertificate = generateTBSCertificate(serialNumber: serialNumber, issuer: issuer, subject: subject, publicKey: publicKey);
        let digest         = generateDigest(for: tbsCertificate);
        let signature      = generateSignature(for: digest, using: privateKey);
        var data           = [UInt8]();
        
        data += tbsCertificate;
        data += encodeAlgorithm(type: PKCS1SHA256WithRSAEncryption);
        data += encoder.encodeBitString(bytes: signature);
        
        return encoder.encodeSequence(bytes: data);
    }
    
    /**
     To-Be-Signed Certificate
     */
    func generateTBSCertificate(serialNumber: [UInt8], issuer: X509Name, subject: X509Name, publicKey: SecKey) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += encoder.encodeContextDefined(id: 0, primitive: false, bytes: encoder.encodeInteger(bytes: Version));
        data += encodeSerialNumber(serialNumber);
        data += encodeAlgorithm(type: PKCS1SHA256WithRSAEncryption);
        data += encodeName(issuer);
        data += encodeValidity();
        data += encodeName(subject);
        data += encodePublicKey(publicKey);
        data += encodeExtensions(publicKey: publicKey, issuer: issuer, serialNumber: serialNumber);
        
        return encoder.encodeSequence(bytes: data);
    }
    
    private func generateDigest(for bytes: [UInt8]) -> [UInt8]
    {
        let digest = SHA256();
        
        digest.update(bytes: bytes);
        return digest.final();
    }
    
    private func generateSerialNumber() -> [UInt8]
    {
        var serialNumber = [UInt8](repeating: 0, count: 8);
        var result       : Int32;
        
        result = SecRandomCopyBytes(kSecRandomDefault, serialNumber.count, &serialNumber);
        if result != errSecSuccess { // TODO: Under what circumstances would this occur?
            fatalError("Unexpected error.");
        }
        
        if (serialNumber[0] & 0x80) == 0x80 {
            return [0] + serialNumber;
        }
        return serialNumber;
    }
    
    private func generateSignature(for bytes: [UInt8], using key: SecKey) -> [UInt8]
    {
        let signature = key.sign(bytes: bytes)!;
        return [0] + signature;
    }
    
    private func encodeAlgorithm(type: [UInt]) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += encoder.encodeObjectIdentifier(components: type);
        data += encoder.encodeNull();
        
        return encoder.encodeSequence(bytes: data);
    }
    
    private func encodeAttributeTypeValue(type: [UInt], value: String) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += encoder.encodeObjectIdentifier(components: type);
        data += encoder.encodePrintableString(value);
        
        return encoder.encodeSet(bytes: encoder.encodeSequence(bytes: data));
    }
    
    private func encodeExtensions(publicKey: SecKey, issuer: X509Name, serialNumber: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += encodeExtSubjectKeyIdentifier(publicKey);
        data += encodeExtAuthorityKeyIdentifier(publicKey, issuer: issuer, serialNumber: serialNumber);
        data += encodeExtBasicConstraints();
        data += encodeExtKeyUsage();
        data  = encoder.encodeSequence(bytes: data);
        
        return encoder.encodeContextDefined(id: 3, primitive: false, bytes: data)!;
    }
    
    private func encodeExtSubjectKeyIdentifier(_ key: SecKey) -> [UInt8]
    {
        let encodedKey    = [UInt8](SecKeyCopyExternalRepresentation(key, nil)! as Data);
        var data          = [UInt8]();
        var keyIdentifier : [UInt8];
        let digest        = SHA1();
        
        digest.update(bytes: [0] + encodedKey);
        keyIdentifier = encoder.encodeOctetString(bytes: digest.final());
        
        data += encoder.encodeObjectIdentifier(components: X509SubjectKeyIdentifier);
        data += encoder.encodeOctetString(bytes: keyIdentifier);
        
        return encoder.encodeSequence(bytes: data)
    }
    
    private func encodeExtAuthorityKeyIdentifier(_ key: SecKey, issuer: X509Name, serialNumber: [UInt8]) -> [UInt8]
    {
        let encodedKey    = [UInt8](SecKeyCopyExternalRepresentation(key, nil)! as Data);
        var data          = [UInt8]();
        var name          : [UInt8]?;
        var value         = [UInt8]();
        var keyIdentifier : [UInt8];
        let digest        = SHA1();
        
        digest.update(bytes: [0] + encodedKey);
        keyIdentifier = encoder.encodeOctetString(bytes: digest.final());
        
        name   = encoder.encodeContextDefined(id: 4, primitive: false, bytes: encodeName(issuer));
        value += encoder.encodeContextDefined(id: 0, primitive: false, bytes: keyIdentifier);
        value += encoder.encodeContextDefined(id: 1, primitive: false, bytes: name);
        value += encoder.encodeContextDefined(id: 2, primitive: true,  bytes: serialNumber);
        value  = encoder.encodeSequence(bytes: value);
        
        data += encoder.encodeObjectIdentifier(components: X509AuthorityKeyIdentifier);
        data += encoder.encodeOctetString(bytes: value);
        
        return encoder.encodeSequence(bytes: data)
    }
    
    private func encodeExtKeyUsage() -> [UInt8]
    {
        var data     = [UInt8]();
        let valueSeq = encoder.encodeBitString(bytes: [ 0x07, 0xff, 0x80]);
        
        data += encoder.encodeObjectIdentifier(components: X509KeyUsage);
        data += encoder.encodeBoolean(true); // critical
        data += encoder.encodeOctetString(bytes: valueSeq);
        
        return encoder.encodeSequence(bytes: data)
    }
    
    private func encodeExtBasicConstraints() -> [UInt8]
    {
        var data     = [UInt8]();
        let value    = encoder.encodeBoolean(true);
        let valueSeq = encoder.encodeSequence(bytes: value);
        
        data += encoder.encodeObjectIdentifier(components: X509BasicConstraints);
        data += encoder.encodeBoolean(true); // critical
        data += encoder.encodeOctetString(bytes: valueSeq);
        
        return encoder.encodeSequence(bytes: data)
    }
    
    private func encodeKey(_ key: SecKey) -> [UInt8]
    {
        let encodedKey = SecKeyCopyExternalRepresentation(key, nil)! as Data;
        let data       = [UInt8](encodedKey);
        
        return [0] + data;
    }
    
    private func encodePublicKey(_ publicKey: SecKey) -> [UInt8]
    {
        var data = [UInt8]();
        let key  = encodeKey(publicKey);

        data += encodeAlgorithm(type: PKCS1RSAEncryption);
        data += encoder.encodeBitString(bytes: key);
        
        return encoder.encodeSequence(bytes: data);
    }
    
    private func encodeSerialNumber(_ serialNumber: [UInt8]) -> [UInt8]
    {
        return encoder.encodeInteger(bytes: serialNumber);
    }
    
    private func encodeValidity() -> [UInt8]
    {
        var data = [UInt8]();
        let from = Date();
        let to   = from.addingTimeInterval(Year);
        
        data += encoder.encodeUTCTime(from);
        data += encoder.encodeUTCTime(to);
        
        return encoder.encodeSequence(bytes: data);
    }
    
    private func encodeName(_ subject: X509Name) -> [UInt8]
    {
        var data = [UInt8]();
        
        if let country = subject.country {
            data += encodeAttributeTypeValue(type: X520CountryName, value: country);
        }
        if let state = subject.state {
            data += encodeAttributeTypeValue(type: X520StateOrProvinceName, value: state);
        }
        if let locality = subject.locality {
            data += encodeAttributeTypeValue(type: X520LocalityName, value: locality);
        }
        if let organization = subject.organization {
            data += encodeAttributeTypeValue(type: X520OrganizationName, value: organization);
        }
        if let organizationUnit = subject.organizationUnit {
            data += encodeAttributeTypeValue(type: X520OrganizationUnitName, value: organizationUnit);
        }
        if let commonName = subject.commonName {
            data += encodeAttributeTypeValue(type: X520CommonName, value: commonName);
        }
        
        return encoder.encodeSequence(bytes: data);
    }
    
}


func +=(lhs: inout [UInt8], rhs: [UInt8]?)
{
    if rhs != nil {
        lhs.append(contentsOf: rhs!);
    }
}


// End of File
