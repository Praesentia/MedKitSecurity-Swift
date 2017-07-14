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
 ASN.1 Distinguished Encoding Rules (DER) decoder.
 */
class DERDecoder: DERCoder {
    
    // MARK: - Properties
    var bytes   : [UInt8] { return Array(slice) }
    var more    : Bool    { return index < slice.endIndex }
    var atEnd   : Bool    { return index == slice.endIndex }
    var nextTag : UInt8?  { return (index < slice.endIndex) ? slice[index] : nil }
    
    // MARK: - Private Properties
    private var slice: ArraySlice<UInt8>
    private var index: Int
    
    // MARK: - Initializers
    
    init(bytes: ArraySlice<UInt8>, index: Int = 0)
    {
        self.slice = bytes
        self.index = slice.startIndex + index
    }
    
    convenience init(bytes: [UInt8], index: Int = 0)
    {
        self.init(bytes: ArraySlice(bytes), index: index)
    }
    
    // MARK: - Assertions
    
    func assert(_ value: Bool) throws
    {
        if !value {
            throw SecurityKitError.failed
        }
    }
    
    func assertAtEnd() throws
    {
        try assert(atEnd)
    }
    
    // MARK: - Peek Primitives
    
    func peekTag() throws -> UInt8
    {
        try assert(index < slice.endIndex)
        return slice[index]
    }
    
    func peekTag(with value: UInt8) -> Bool
    {
        if let tag = nextTag {
            return tag == value
        }
        
        return false
    }
    
    // MARK: - Decoding Primitives
    
    func decode(with: UInt8) throws -> [UInt8]
    {
        let tag = try decodeTag()
        try assert(tag == with)
        
        let length = try decodeLength()
        return try getContent(length)
    }
    
    func decodeBoolean() throws -> Bool
    {
        let bytes = try decode(with: DERCoder.TagBoolean)
        
        try assert(bytes.count == 1)
        try assert(bytes[0] == 0xff || bytes[0] == 0x00)
        
        return bytes[0] == 0xff
    }
    
    func decodeBitString() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagBitString)
    }
    
    func decodeInteger() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagInteger)
    }
    
    func decodeUnsignedInteger() throws -> [UInt8]
    {
        let bytes = try decode(with: DERCoder.TagInteger)
        
        if bytes[0] == 0x00 {
            return Array(bytes[1..<bytes.count])
        }
        return bytes
    }
    
    func decodeNull() throws -> [UInt8]
    {
        let bytes = try decode(with: DERCoder.TagNull)
        
        try assert(bytes.count == 0)
        return bytes
    }

    func decodeObjectIdentifier() throws -> [UInt]
    {
        let bytes = try decode(with: DERCoder.TagObjectIdentifier)
        try assert(bytes.count > 0)

        var oid      = [UInt]()
        let oid0     = bytes[0] / 40
        let oid1     = bytes[0] - (oid0 * 40)
        var index    : Int  = 1
        var component: UInt = 0
        
        oid.append(UInt(oid0))
        oid.append(UInt(oid1))
        
        while index < bytes.count { // TODO: error check
            let byte = bytes[index]
            
            if byte < 0x80 {
                component = (component << 7) | UInt(byte)
                oid.append(component)
                component = 0
            }
            else {
                component = (component << 7) | UInt(byte & 0x7f)
            }
            
            index += 1
        }
        
        return oid
    }
    
    func decodeOctetString() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagOctetString)
    }
    
    func decodePrintableString() throws -> String
    {
        let bytes = try decode(with: DERCoder.TagPrintableString)
        
        if let string = String(bytes: bytes, encoding: .ascii) {
            return string
        }
        
        throw SecurityKitError.failed
    }
    
    func decodePrintableString() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagPrintableString)
    }
    
    func decoderFromOctetString() throws -> DERDecoder
    {
        return try decoderFromTag(with: DERCoder.TagOctetString)
    }
    
    func decoderFromSequence() throws -> DERDecoder
    {
        return try decoderFromTag(with: DERCoder.TagSequence)
    }
    
    func decoderFromSet() throws -> DERDecoder
    {
        return try decoderFromTag(with: DERCoder.TagSet)
    }
    
    func decoderFromTag(with: UInt8) throws -> DERDecoder
    {
        let start = index
        let tag   = try decodeTag()
        
        try assert(tag == with)
        
        let length = try decodeLength()
        let data   = index
        try advance(count: length)
        
        return DERDecoder(bytes: slice[start..<index], index: data - start)
    }
    
    func decodeSequence() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagSequence)
    }
    
    func decodeSet() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagSet)
    }
    
    func decodeUTCTime() throws -> Date
    {
        let bytes = try decode(with: DERCoder.TagUTCTime)
        
        if let string = String(bytes: bytes, encoding: .ascii) {
            if let date = DERCoder.dateFormatterUTC.date(from: string) {
                return date
            }
        }
        
        throw SecurityKitError.failed
    }
    
    func decodeUniversalTime() throws -> Date
    {
        let bytes = try decode(with: DERCoder.TagUTCTime)
        
        if let string = String(bytes: bytes, encoding: .ascii) {
            if let date = DERCoder.dateFormatterUniversal.date(from: string) {
                return date
            }
        }
        
        throw SecurityKitError.failed
    }
    
    func decodeUTF8String() throws -> String
    {
        let bytes = try decode(with: DERCoder.TagUTF8String)
        
        if let string = String(bytes: bytes, encoding: .utf8) {
            return string
        }

        throw SecurityKitError.failed
    }
    
    func decodeUTF8String() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagUTF8String)
    }
    
    func decodeIA5String() throws -> String
    {
        let bytes = try decode(with: DERCoder.TagIA5String)
        
        if let string = String(bytes: bytes, encoding: .ascii) { // TODO
            return string
        }
        
        throw SecurityKitError.failed
    }
    
    func decodeIA5String() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagIA5String)
    }
    
    // MARK: - Private
    
    private func decodeTag() throws -> UInt8
    {
        return try getByte()
    }
    
    private func decodeLength() throws -> Int
    {
        var byte = try getByte()
        
        if byte != 0x80 {
            
            if byte < 0x80 {
                return Int(byte)
            }
            
            var length = 0
            let count  = byte & 0x7f
            
            // TODO
            for _ in 0..<count {
                byte   = try getByte()
                length = (length << 8) + Int(byte)
            }
            
            return length
        }
        
        throw SecurityKitError.failed
    }
    
    private func getByte() throws -> UInt8
    {
        if index < slice.endIndex {
            let byte = slice[index]
            
            index += 1
            return byte
        }
        
        throw SecurityKitError.failed
    }
    
    private func advance(count: Int) throws
    {
        let end = index + count
        
        try assert(end <= slice.endIndex)
        index = end
    }
    
    private func getContent(_ count: Int) throws -> [UInt8]
    {
        let end = index + count
        
        if end <= slice.endIndex {
            let content = [UInt8](slice[index..<end])
            
            index += count
            
            return content
        }
        
        throw SecurityKitError.failed
    }
    
}


// End of File
