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


struct CertificationRequestInfo: DERCodable {
    
    // MARK: - Properties
    let version              : UInt = 0
    var subject              : X509Name
    var subjectPublicKeyInfo : X509SubjectPublicKeyInfo
    var attributes           : [UInt8]?
    
    init(subject: X509Name, subjectPublicKeyInfo: X509SubjectPublicKeyInfo)
    {
        self.subject              = subject
        self.subjectPublicKeyInfo = subjectPublicKeyInfo
    }
    
    // MARK: - DERCodable
    
    func encode(encoder: DEREncoder) -> [UInt8]
    {
        var bytes = [UInt8]()
        
        bytes += encoder.encode(version)
        bytes += encoder.encode(subject)
        bytes += encoder.encode(subjectPublicKeyInfo)
        
        return encoder.encodeSequence(bytes: bytes)
    }
    
}


// End of File
