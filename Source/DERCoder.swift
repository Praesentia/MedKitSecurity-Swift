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


/**
 ASN.1 Distinguished Encoding Rules (DER) coder base class.
 */
class DERCoder {
    
    // MARK: - Tag Constants
    static let TagBoolean          : UInt8 = 0x01
    static let TagInteger          : UInt8 = 0x02
    static let TagBitString        : UInt8 = 0x03
    static let TagOctetString      : UInt8 = 0x04
    static let TagNull             : UInt8 = 0x05
    static let TagObjectIdentifier : UInt8 = 0x06
    static let TagObjectDescriptor : UInt8 = 0x07
    static let TagObjectReal       : UInt8 = 0x09
    static let TagEnumerated       : UInt8 = 0x0a
    static let TagUTF8String       : UInt8 = 0x0c
    static let TagPrintableString  : UInt8 = 0x13
    static let TagTeletexString    : UInt8 = 0x14
    static let TagVideotexString   : UInt8 = 0x15
    static let TagIA5String        : UInt8 = 0x16
    static let TagUTCTime          : UInt8 = 0x17
    static let TagSequence         : UInt8 = 0x30
    static let TagSet              : UInt8 = 0x31
    
    // MARK: - Contextual Tag Constants
    static let ContextDefined      : UInt8 = 0x80
    static let Constructed         : UInt8 = 0x20
    
    // MARK: - Date/Time Formatter
    static let dateFormatterUTC       = DateFormatter(dateFormat: "yyMMddHHmmss'Z'",   timeZone: TimeZone(abbreviation: "UTC")!)
    static let dateFormatterUniversal = DateFormatter(dateFormat: "yyyyMMddHHmmss'Z'", timeZone: TimeZone(abbreviation: "UTC")!)
    
    // MARK: - Initializers
    
    init()
    {
    }
    
    // MARK: - Utility Methods
    
    class func makeContextDefinedTag(id: UInt8, primitive: Bool) -> UInt8
    {
        if primitive {
            return DERCoder.ContextDefined | id
        }
        return DERCoder.ContextDefined | DERCoder.Constructed | id
    }
    
}


// End of File
