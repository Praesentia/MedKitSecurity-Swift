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


/**
 ASN.1 Distinguished Encoding Rules (DER) encoder.
 */
class DEREncoder: DERCoder {
    
    // MARK: - Encoders
    
    func encode(_ codable: DERCodable) -> [UInt8]
    {
        return codable.encode(encoder: self)
    }
    
    func encode(_ codable: DERCodable?) -> [UInt8]?
    {
        if let codable = codable {
            return codable.encode(encoder: self)
        }
        return nil
    }
    
    func encodeBoolean(_ value: Bool) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagBoolean
        data += encodeLength(1)
        data += value ? [ 0xff ] : [ 0x00 ]
        
        return data
    }
    
    func encodeContextDefined(id: UInt8, primitive: Bool, bytes: [UInt8]?) -> [UInt8]?
    {
        if let bytes = bytes {
            var data = [UInt8]()
            
            data += DERCoder.makeContextDefinedTag(id: id, primitive: primitive)
            data += encodeLength(bytes.count)
            data += bytes
            
            return data
        }
        
        return nil
    }
    
    func encodeInteger(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagInteger
        data += encodeLength(bytes.count)
        data += bytes
        
        return data
    }
    
    func encodeUnsignedInteger(_ value: UInt) -> [UInt8]
    {
        var bytes = [UInt8]()
        var n     = value
        
        bytes.append(UInt8(n & 0xff))
        
        while n > 0xff {
            n = n >> 8
            bytes.append(UInt8(n & 0xff))
        }
        
        return encodeUnsignedInteger(bytes: bytes.reversed())
    }
    
    func encodeUnsignedInteger(bytes: [UInt8]) -> [UInt8]
    {
        if (bytes[0] & 0x80) == 0x80 {
            return encodeInteger(bytes: [0] + bytes)
        }
        return encodeInteger(bytes: bytes)
    }
    
    func encodeKeyValue(key: [UInt8], value: String) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += key
        data += encodeUTF8String(value)

        data = encodeSequence(bytes: data)
        data = encodeSet(bytes: data)
        
        return data
    }
    
    func encodeLength(_ length: Int) -> [UInt8]
    {
        Swift.assert(length < 0x8000)
        
        if length < 0x80 {
            return [UInt8(length)]
        }
        
        if length < 0x100 {
            return [0x81, UInt8(length & 0xff)]
        }
        
        return [0x82, UInt8(length >> 8 & 0xff), UInt8(length & 0xff)]
    }
    
    func encodeBitString(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagBitString
        data += encodeLength(bytes.count)
        data += bytes
        
        return data
    }
    
    func encodeOctetString(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagOctetString
        data += encodeLength(bytes.count)
        data += bytes
        
        return data
    }
    
    func encodeNull() -> [UInt8]
    {
        return [ DERCoder.TagNull, 0x00 ]
    }
    
    func encodeObjectIdentifier(components: [UInt]) -> [UInt8]
    {
        var data  = [UInt8]()
        var value = [UInt8]()
        
        value += [UInt8(40 * components[0] + components[1])]
        
        for i in 2..<components.count {
            var component = components[i]
            var fragment  = [UInt8]()
            
            fragment.append(UInt8(component & 0x7f))
            
            while component >= 0x80 {
                component = component >> 7
                fragment.append(UInt8(component & 0x7f | 0x80))
            }
            
            value += fragment.reversed()
        }
        
        data += DERCoder.TagObjectIdentifier
        data += encodeLength(value.count)
        data += value
        
        return data
    }
    
    func encodeSequence(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagSequence
        data += encodeLength(bytes.count)
        data += bytes
        
        return data
    }
    
    func encodeSet(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagSet
        data += encodeLength(bytes.count)
        data += bytes
        
        return data
    }
    
    func encodeIA5String(_ value: String) -> [UInt8]
    {
        var data       = [UInt8]()
        let characters : [UInt8] = value.unicodeScalars.map { UInt8($0.value) }
        
        data += DERCoder.TagIA5String
        data += encodeLength(characters.count)
        data += characters
        
        return data
    }
    
    func encodeIA5String(_ value: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagIA5String
        data += encodeLength(value.count)
        data += value
        
        return data
    }
    
    func encodePrintableString(_ value: String) -> [UInt8]
    {
        var data       = [UInt8]()
        let characters : [UInt8] = value.unicodeScalars.map { UInt8($0.value) }
        
        data += DERCoder.TagPrintableString
        data += encodeLength(characters.count)
        data += characters
        
        return data
    }
    
    func encodePrintableString(_ value: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagPrintableString
        data += encodeLength(value.count)
        data += value
        
        return data
    }
    
    func encodeUTCTime(_ date: Date) -> [UInt8]
    {
        var data      = [UInt8]()
        let utcString = DERCoder.dateFormatterUTC.string(from: date)
        let utc       = utcString.unicodeScalars.map { UInt8($0.value) }
        
        data += DERCoder.TagUTCTime
        data += encodeLength(utc.count)
        data += utc
        
        return data
    }
    
    func encodeUniversalTime(_ date: Date) -> [UInt8]
    {
        var data      = [UInt8]()
        let utcString = DERCoder.dateFormatterUniversal.string(from: date)
        let utc       = utcString.unicodeScalars.map { UInt8($0.value) }
        
        data += DERCoder.TagUTCTime
        data += encodeLength(utc.count)
        data += utc
        
        return data
    }
    
    func encodeUTF8String(_ value: String) -> [UInt8]
    {
        var data = [UInt8]()
        let utf8 = value.utf8
        
        data += DERCoder.TagUTF8String
        data += encodeLength(utf8.count)
        data += utf8
        
        return data
    }
    
    func encodeUTF8String(_ value: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]()
        
        data += DERCoder.TagUTF8String
        data += encodeLength(value.count)
        data += value
        
        return data
    }
    
}


// End of File
