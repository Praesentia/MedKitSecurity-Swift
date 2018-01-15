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
 Shared secret credentials.
 */
class SharedSecretCredentialsImpl: SharedSecretCredentials {

    // MARK: - Properties
    public let identity : Identity?
    public let key      : SharedSecretKey
    public var type     : CredentialsType    { return .sharedSecret }
    public var validity : ClosedRange<Date>? { return nil } // TODO

    // MARK: - Private
    private enum CodingKeys: CodingKey {
        case identity
        case key
    }

    private let digestType: DigestType = .sha256
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    init(for identity: Identity, with key: SharedSecretKeyImpl)
    {
        self.identity = identity
        self.key      = key
    }

    // MARK: - Codable

    required init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        identity = try container.decode(Identity.self,            forKey: .identity)
        key      = try container.decode(SharedSecretKeyImpl.self, forKey: .key)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(identity,               forKey: .identity)
        try container.encode(ConcreteEncodable(key), forKey: .key)
    }
    
    // MARK: - Authentication
    
    public func verifyTrust(completionHandler completion: @escaping (Error?) -> Void)
    {
        completion(nil)
    }
    
    // MARK: Signing
    
    public func sign(data: Data, using digestType: DigestType) -> Data?
    {
        return key.sign(data: data, using: digestType)
    }
    
    public func verify(signature: Data, for data: Data, using digestType: DigestType) -> Bool
    {
        return key.verify(signature: signature, for: data, using: digestType)
    }
    
}


// End of File
