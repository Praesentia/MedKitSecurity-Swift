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


// Names
let X520IDAT                   : [UInt]  = [ 2, 5, 4 ]
let X520CommonName             : [UInt]  = X520IDAT + [  3 ]
let X520CountryName            : [UInt]  = X520IDAT + [  6 ]
let X520LocalityName           : [UInt]  = X520IDAT + [  7 ]
let X520StateOrProvinceName    : [UInt]  = X520IDAT + [  8 ]
let X520OrganizationName       : [UInt]  = X520IDAT + [ 10 ]
let X520OrganizationUnitName   : [UInt]  = X520IDAT + [ 11 ]

// Extensions
let X509IDCE                       : [UInt]  = [ 2, 5, 29 ]
let X509ExtnSubjectKeyIdentifier   : [UInt]  = X509IDCE + [ 14 ]
let X509ExtnKeyUsage               : [UInt]  = X509IDCE + [ 15 ]
let X509ExtnBasicConstraints       : [UInt]  = X509IDCE + [ 19 ]
let X509ExtnAuthorityKeyIdentifier : [UInt]  = X509IDCE + [ 35 ]
let X509ExtnExtendedKeyUsage       : [UInt]  = X509IDCE + [ 37 ]


// End of File
