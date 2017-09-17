/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
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
 Private Key
 */
class PublicKeyRSA: PublicKey {
    
    // MARK: - Properties
    public let              algorithm           = X509Algorithm.rsaEncryption
    public let              encryptionAlgorithm = PublicKeyEncryptionAlgorithm.rsa
    public var              keySize             : UInt { return UInt(modulus.count) * 8 }
    public private(set) var privateKey          : PrivateKey?

    // MARK: - Internal Properties
    var        bytes               : [UInt8]  { return [UInt8](data) }
    var        data                : Data     { return key.data! }
    let        modulus             : [UInt8]
    let        exponent            : [UInt8]
    let        key                 : SecKey
    
    // MARK: - Initializers
    
    init(_ key: SecKey)
    {
        let decoder = DERDecoder(bytes: [UInt8](key.data!))
        
        (modulus, exponent) = try! PublicKeyRSA.decode(decoder)
        
        self.key        = key
        self.privateKey = KeyStore.main.loadPrivateKey(for: self)
    }
    
    init(from data: Data) throws
    {
        let decoder = DERDecoder(bytes: [UInt8](data))
        
        (modulus, exponent) = try PublicKeyRSA.decode(decoder)
        key                 = SecKey.create(from: data, withKeySize: UInt(modulus.count) * 8)!
        privateKey          = KeyStore.main.loadPrivateKey(for: self)
    }
    
    // MARK: -
    
    private static func decode(_ decoder: DERDecoder) throws -> ([UInt8], [UInt8])
    {
        let sequence = try decoder.decoderFromSequence()
        let modulus  = try sequence.decodeUnsignedInteger()
        let exponent = try sequence.decodeUnsignedInteger()
        
        try sequence.assertAtEnd()
        try decoder.assertAtEnd()
        
        return (modulus, exponent)
    }
    
    // MARK: Fingerprint
    
    public func fingerprint(using digestType: DigestType) -> [UInt8]
    {
        let digest = instantiateDigest(ofType: digestType)
        return digest.hash(bytes: bytes)
    }
    
    // MARK: - Signing
    
    func sign(bytes: [UInt8], using digestType: DigestType) -> [UInt8]
    {
        let digest = instantiateDigest(ofType: digestType)
        return key.sign(bytes: digest.hash(bytes: bytes), padding: digestType.padding)!
    }
    
    func verify(signature: [UInt8], for bytes: [UInt8], using digestType: DigestType) -> Bool
    {
        let digest = instantiateDigest(ofType: digestType)
        let hash   = digest.hash(bytes: bytes)
        return key.verify(signature: signature, for: hash, padding: digestType.padding)
    }
    
}


// End of File
