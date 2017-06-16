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


let PKCS1RSAEncryption           : [UInt]  = [ 1, 2, 840, 113549, 1, 1,  1 ];
let PKCS1MD2WithRSAEncryption    : [UInt]  = [ 1, 2, 840, 113549, 1, 1,  2 ];
let PKCS1MD5WithRSAEncryption    : [UInt]  = [ 1, 2, 840, 113549, 1, 1,  4 ];
let PKCS1SHA1WithRSAEncryption   : [UInt]  = [ 1, 2, 840, 113549, 1, 1,  5 ];
let PKCS1SHA256WithRSAEncryption : [UInt]  = [ 1, 2, 840, 113549, 1, 1, 11 ];
let PKCS1SHA384WithRSAEncryption : [UInt]  = [ 1, 2, 840, 113549, 1, 1, 12 ];
let PKCS1SHA512WithRSAEncryption : [UInt]  = [ 1, 2, 840, 113549, 1, 1, 13 ];


// End of File
