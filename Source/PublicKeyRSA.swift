/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
 Copyright 2017-2018 Jon Griffeth
 
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
    public var              keySize             : UInt { return keyData.size }
    public private(set) var privateKey          : PrivateKey?

    // MARK: - Internal Properties
    var data     : Data { return key.data! }
    var keyData  : PKCS1RSAPublicKey
    let key      : SecKey
    
    // MARK: - Initializers
    
    init(_ key: SecKey)
    {
        self.keyData    = try! DERDecoder().decode(PKCS1RSAPublicKey.self, from: key.data!)
        self.key        = key
        self.privateKey = KeyStore.main.loadPrivateKey(for: self)
    }
    
    init(from data: Data) throws
    {
        keyData    = try! DERDecoder().decode(PKCS1RSAPublicKey.self, from: data)
        key        = SecKey.create(from: data, withKeySize: keyData.size)!
        privateKey = KeyStore.main.loadPrivateKey(for: self)
    }
    
    // MARK: Fingerprint
    
    public func fingerprint(using digestType: DigestType) -> Data
    {
        let digest = instantiateDigest(ofType: digestType)
        return digest.hash(data: data)
    }
    
    // MARK: - Signing
    
    func sign(data: Data, using digestType: DigestType) -> Data
    {
        let digest = instantiateDigest(ofType: digestType)
        return key.sign(data: digest.hash(data: data), padding: digestType.padding)!
    }
    
    func verify(signature: Data, for data: Data, using digestType: DigestType) -> Bool
    {
        let digest = instantiateDigest(ofType: digestType)
        let hash   = digest.hash(data: data)
        return key.verify(signature: signature, for: hash, padding: digestType.padding)
    }
    
}


// End of File
