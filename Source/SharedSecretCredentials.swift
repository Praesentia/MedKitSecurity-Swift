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
 Shared secret credentials.
 */
class SharedSecretCredentials: Credentials {
    
    // MARK: - Properties
    public let identity : Identity?
    public var profile  : Any                { return getProfile() }
    public var type     : CredentialsType    { return .sharedSecret }
    public var validity : ClosedRange<Date>? { return nil } // TODO
    
    // MARK: - Private Properties
    private let digestType: DigestType = .sha256
    private let key       : Key
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    init(for identity: Identity, with key: Key)
    {
        self.identity = identity
        self.key      = key
    }
    
    // MARK: - Authentication
    
    public func verifyTrust(completionHandler completion: @escaping (Error?) -> Void)
    {
        completion(nil)
    }
    
    // MARK: Signing
    
    public func sign(bytes: [UInt8], using digestType: DigestType) -> [UInt8]?
    {
        return key.sign(bytes: bytes, using: digestType)
    }
    
    public func verify(signature: [UInt8], for bytes: [UInt8], using digestType: DigestType) -> Bool
    {
        return key.verify(signature: signature, for: bytes, using: digestType)
    }

    // MARK: - Private
    
    /**
     Get profile.
     
     Generates a JSON profile representing the credentials.  In this case, the
     profile only includes the credentials type, as both sides are expected to
     know the secret.
     
     - Returns:
        Returns the generated JSON profile.
     */
    private func getProfile() -> Any
    {
        var profile = [String : Any]()
        
        profile[KeyType]     = type.string
        profile[KeyIdentity] = identity?.string
        
        return profile
    }
    
}


// End of File
