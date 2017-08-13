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


import SecurityKit
import XCTest


// Test Certificate Authority (CA)
let testCAIdentity    = Identity(named: "TestCA", type: .other)
let testCAName        = X509Name(from: testCAIdentity)
let testCAP12URL      = Bundle.tests.url(forResource: "TestCA", ofType: "p12")!
let testCAP12Password = "TestCA"
let testCACerURL      = Bundle.tests.url(forResource: "TestCA", ofType: "cer")!

// Test Certificate
let testIdentity      = Identity(named: "Test", type: .user)
let testName          = X509Name(from: testIdentity)
let testCerURL        = Bundle.tests.url(forResource: "Test", ofType: "cer")!
let testCerData       = try! Data(contentsOf: testCerURL)

let Minute  = TimeInterval(60)
let Hour    = TimeInterval(60 * Minute)
let Day     = TimeInterval(24 * Hour)
let Year    = TimeInterval(365 * Day)
let OneYear = Year


// End of File
