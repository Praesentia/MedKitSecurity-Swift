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
 Shared Secret Key
 */
class SharedSecretKeyImpl: SharedSecretKey {
    
    // MARK: - Properties
    public let encryptionAlogrithm : SymmetricEncryptionAlgorithm
    public var keySize             : UInt { return UInt(secret.count) * 8 }

    // MARK: - Private
    private enum CodingKeys: CodingKey {
        case encryptionAlgorithm
        case secret
    }

    private let secret: Data
    
    // MARK: - Initializers
    
    init(with secret: Data, using encryptionAlgorithm: SymmetricEncryptionAlgorithm)
    {
        self.encryptionAlogrithm = encryptionAlgorithm
        self.secret              = secret
    }

    // MARK: - Codable

    required init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let base64    = try container.decode(String.self, forKey: .secret)

        encryptionAlogrithm = try container.decode(SymmetricEncryptionAlgorithm.self, forKey: .encryptionAlgorithm)
        secret              = try Data(base64encoded: base64)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(encryptionAlogrithm,          forKey: .encryptionAlgorithm)
        try container.encode(secret.base64EncodedString(), forKey: .secret)
    }

    // MARK: - Signing
    
    func sign(data: Data, using digestType: DigestType) -> Data
    {
        let hmac = instantiateHMAC(using: digestType)
        return hmac.sign(data: data, using: secret)
    }
    
    func verify(signature: Data, for data: Data, using digestType: DigestType) -> Bool
    {
        let hmac = instantiateHMAC(using: digestType)
        return signature == hmac.sign(data: data, using: secret)
    }
    
}


// End of File
