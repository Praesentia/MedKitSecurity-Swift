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


extension SecurityKitError {
    
    private static let osstatusMap: [OSStatus : SecurityKitError] = [
        errSecInvalidData        : .invalidData,
        errSecMissingEntitlement : .notPermitted
    ]

    init?(from osstatus: OSStatus)
    {
        switch osstatus {
        case errSecSuccess :
            return nil
            
        default :
            self = SecurityKitError.osstatusMap[osstatus] ?? SecurityKitError.failed
        }
    }
    
    init?(from error: Error?)
    {
        switch error {
        case nil :
            return nil
            
        case let error as NSError :
            if error.domain == NSOSStatusErrorDomain {
                self = SecurityKitError.osstatusMap[Int32(error.code)] ?? .failed
            }
            else {
                self = .failed
            }
            
        case let error as SecurityKitError :
            self = error
            
        default :
            self = .failed
        }
    }
    
}


// End of File
