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


func instantiateHMAC(using digestType: DigestType) -> HMAC
{
    switch digestType {
    case .md5 :
        return HMACMD5()
    
    case .sha1 :
        return HMACSHA1()
        
    case .sha224 :
        return HMACSHA224()
        
    case .sha256 :
        return HMACSHA256()
        
    case .sha384 :
        return HMACSHA384()
        
    case .sha512 :
        return HMACSHA512()
    }
}


// End of File
