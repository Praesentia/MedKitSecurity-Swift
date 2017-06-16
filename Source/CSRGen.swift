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


class CSRGen {
    
    // MARK: Private Constants
    private let Version              : [UInt8] = [ 0x00 ];
    private let CommonName           : [UInt8] = [ 0x06, 0x03, 0x55, 0x04, 0x03 ];
    private let CountryName          : [UInt8] = [ 0x06, 0x03, 0x55, 0x04, 0x06 ];
    private let OrganizationName     : [UInt8] = [ 0x06, 0x03, 0x55, 0x04, 0x0a ];
    private let OrganizationUnitName : [UInt8] = [ 0x06, 0x03, 0x55, 0x04, 0x0b ];
    private let Attributes           : [UInt8] = [ 0xa0, 0x00 ];
    private let RSAEncryption        : [UInt8] = [ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 ];
    private let SHA1WithRSAEncryption: [UInt8] = [ 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 5, 0x05, 0x00 ];
    
    // MARK: - Private
    private let encoder = DER();
    
    // MARK: - Initializers
    
    init()
    {
    }
    
    // MARK: -
    
    func generateCSR(subject: X509Name, publicKey: SecKey, privateKey: SecKey) -> [UInt8]
    {
        let csrInfo   = generateCSRInfo(subject: subject, publicKey: publicKey);
        let digest    = generateDigest(bytes: csrInfo);
        let signature = generateSignature(bytes: digest, privateKey: privateKey);
        var data      = [UInt8]();
        
        data += SHA1WithRSAEncryption;
        data += csrInfo;
        data += [0] + digest;
        data += encoder.encodeBitString(bytes: signature);
        
        return encoder.encodeSequence(bytes: data);
    }
    
    func generateCSRInfo(subject: X509Name, publicKey: SecKey) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += encoder.encodeInteger(bytes: Version);
        data += encodeSubject(subject);
        data += encodePublicKey(publicKey);
        data += Attributes;
        
        return encoder.encodeSequence(bytes: data);
    }
    
    private func generateDigest(bytes: [UInt8]) -> [UInt8]
    {
        let sha1 = SHA1();

        sha1.update(bytes: bytes);
        return sha1.final();
    }
    
    private func generateSignature(bytes: [UInt8], privateKey: SecKey) -> [UInt8]
    {
        return [];
    }
    
    private func encodeKey(_ key: SecKey) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += encoder.encodeInteger(bytes: key.mod);
        data += encoder.encodeInteger(bytes: key.exp);
        data  = encoder.encodeSequence(bytes: data);
        data  = [0] + data; // ?
        
        return data;
    }
    
    private func encodePublicKey(_ publicKey: SecKey) -> [UInt8]
    {
        let key  = encodeKey(publicKey);
        var data = [UInt8]();
        
        data += encoder.encodeSequence(bytes: RSAEncryption);
        data += encoder.encodeBitString(bytes: key);
        
        return encoder.encodeSequence(bytes: data);
    }
    
    private func encodeSubject(_ subject: X509Name) -> [UInt8]
    {
        var data = [UInt8]();
        
        if let commonName = subject.commonName {
            data += encoder.encodeKeyValue(key: CommonName, value: commonName);
        }
        if let countryName = subject.country {
            data += encoder.encodeKeyValue(key: CountryName, value: countryName);
        }
        if let organizationName = subject.organization {
            data += encoder.encodeKeyValue(key: OrganizationName, value: organizationName);
        }
        if let organizationUnitName = subject.organizationUnit {
            data += encoder.encodeKeyValue(key: OrganizationUnitName, value: organizationUnitName);
        }
        
        return encoder.encodeSequence(bytes: data);
    }
    
}

extension SecKey {
    
    var exp: [UInt8] { return []; }
    var mod: [UInt8] { return []; }
    
    /*
    + (NSData *)getPublicKeyExp:(NSData *)publicKeyBits
    {
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
    iterator += mod_size;
    
    iterator++; // TYPE - bit stream exp
    int exp_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
    
    return [publicKeyBits subdataWithRange:NSMakeRange(iterator, exp_size)];
    }
    
    +(NSData *)getPublicKeyMod:(NSData *)publicKeyBits
    {
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
    
    return [publicKeyBits subdataWithRange:NSMakeRange(iterator, mod_size)];
    }
    
    +(int)derEncodingGetSizeFrom:(NSData*)buf at:(int*)iterator
    {
    const uint8_t* data = [buf bytes];
    int itr = *iterator;
    int num_bytes = 1;
    int ret = 0;
    
    if (data[itr] > 0x80) {
    num_bytes = data[itr] - 0x80;
    itr++;
    }
    
    for (int i = 0 ; i < num_bytes; i++) ret = (ret * 0x100) + data[itr + i];
    
    *iterator = itr + num_bytes;
    return ret;
    }
    */
    
}


// End of File
