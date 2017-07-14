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


extension SecCertificate {
    
    var commonName: String? { return getCommonName() }
    var data      : Data    { return SecCertificateCopyData(self) as Data }
    var publicKey : SecKey? { return SecCertificateCopyPublicKey(self) }
    
    private func getCommonName() -> String?
    {
        var commonName: CFString?
    
        let status = SecCertificateCopyCommonName(self, &commonName)
        return (status == errSecSuccess) ? commonName as String? : nil
    }
    
}


// End of File
