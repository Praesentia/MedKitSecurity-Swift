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


import Foundation;
import MedKitCore;


/**
 Private Key
 */
class PublicKey: Key {
    
    // MARK: - Properties
    public var blockSize: Int { return SecKeyGetBlockSize(key); }
    
    // MARK: Private Properties
    private let key: SecKey;
    
    // MARK: - Initializers
    
    init(_ key: SecKey)
    {
        self.key = key;
    }
    
    // MARK: - Signing
    
    func sign(bytes: [UInt8]) -> [UInt8]
    {
        return key.sign(bytes: bytes)!;
    }
    
    func verify(signature: [UInt8], for bytes: [UInt8]) -> Bool
    {
        return key.verify(signature: signature, for: bytes);
    }
    
}


// End of File
