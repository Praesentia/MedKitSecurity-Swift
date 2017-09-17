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


extension SecIdentity {
    
    var certificate : SecCertificate? { return getCertificate() }
    var privateKey  : SecKey?         { return getPrivateKey()  }
    
    private func getCertificate() -> SecCertificate?
    {
        var certificate: SecCertificate?
        
        let status = SecIdentityCopyCertificate(self, &certificate)
        return (status == errSecSuccess) ? certificate : nil
    }
    
    private func getPrivateKey() -> SecKey?
    {
        var privateKey: SecKey?

        let status = SecIdentityCopyPrivateKey(self, &privateKey)
        return (status == errSecSuccess) ? privateKey : nil
    }
    
}


// End of File
