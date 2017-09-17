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


extension SecTrust {

    // MARK: - Properities
    var anchorCertificates : [SecCertificate]? { return getAnchorCertificates() }
    var certificateCount   : Int               { return SecTrustGetCertificateCount(self) }

    // MARK: -

    func certificate(at index: Int) -> SecCertificate?
    {
        return SecTrustGetCertificateAtIndex(self, index)
    }

    func evaluate(_ result: inout SecTrustResultType) -> OSStatus
    {
        return SecTrustEvaluate(self, &result)
    }

    func setAnchorCertificates(_ certificates: [SecCertificate]) -> OSStatus
    {
        return SecTrustSetAnchorCertificates(self, certificates as CFArray)
    }

    // MARK: - Private

    private func getAnchorCertificates() -> [SecCertificate]?
    {
        var array              : CFArray?
        var anchorCertificates : [SecCertificate]?

        let status = SecTrustCopyCustomAnchorCertificates(self, &array)
        if status == errSecSuccess, let array = array as? [SecCertificate] {
            anchorCertificates = array
        }

        return anchorCertificates
    }

}


// End of File

