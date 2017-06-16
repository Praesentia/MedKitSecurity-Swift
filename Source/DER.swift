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


class DER {
    
    // MARK: - Private Constants
    private let ContextDefined      = UInt8(0x80);
    private let Constructed         = UInt8(0x20);
    private let TagBoolean          : [UInt8] = [ 0x01 ];
    private let TagInteger          : [UInt8] = [ 0x02 ];
    private let TagBitString        : [UInt8] = [ 0x03 ];
    private let TagOctetString      : [UInt8] = [ 0x04 ];
    private let TagObjectIdentifier : [UInt8] = [ 0x06 ];
    private let TagString           : [UInt8] = [ 0x0C ];
    private let TagPrintableString  : [UInt8] = [ 0x13 ];
    private let TagUTCTime          : [UInt8] = [ 0x17 ];
    private let TagSequence         : [UInt8] = [ 0x30 ];
    private let TagSet              : [UInt8] = [ 0x31 ];
    
    private let dateFormatter = DateFormatter();
    
    // MARK: - Initializers
    
    init()
    {
        dateFormatter.dateFormat = "yyMMddHHmmss";
    }
    
    // MARK: - Encoders
    
    func encodeBoolean(_ value: Bool) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += TagBoolean;
        data += encodeLength(1);
        data += value ? [ 0xff ] : [ 0x00 ];
        
        return data;
    }
    
    func encodeContextDefined(id: UInt8, primitive: Bool, bytes: [UInt8]?) -> [UInt8]?
    {
        if let bytes = bytes {
            let tag  : UInt8;
            var data = [UInt8]();
            
            if primitive {
                tag  = ContextDefined | id;
            }
            else {
                tag  = ContextDefined | Constructed | id;
            }
            
            data += [ tag ];
            data += encodeLength(bytes.count);
            data += bytes;
            
            return data;
        }
        
        return nil;
    }
    
    func encodeKeyValue(key: [UInt8], value: String) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += key;
        data += encodeUTF8String(value);

        data = encodeSequence(bytes: data);
        data = encodeSet(bytes: data);
        
        return data;
    }
    
    func encodeLength(_ length: Int) -> [UInt8]
    {
        assert(length < 0x8000);
        
        if length < 0x80 {
            return [UInt8(length)];
        }
        
        if length < 0x100 {
            return [0x81, UInt8(length & 0xff)];
        }
        
        return [0x82, UInt8(length >> 8 & 0xff), UInt8(length & 0xff)];
    }
    
    func encodeInteger(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += TagInteger;
        data += encodeLength(bytes.count);
        data += bytes;
        
        return data;
    }
    
    func encodeBitString(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += TagBitString;
        data += encodeLength(bytes.count);
        data += bytes;
        
        return data;
    }
    
    func encodeOctetString(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += TagOctetString;
        data += encodeLength(bytes.count);
        data += bytes;
        
        return data;
    }
    
    func encodeNull() -> [UInt8]
    {
        return [ 0x05, 0x00 ];
    }
    
    func encodeObjectIdentifier(components: [UInt]) -> [UInt8]
    {
        var data  = [UInt8]();
        var value = [UInt8]();
        
        value += [UInt8(40 * components[0] + components[1])];
        
        for i in 2..<components.count {
            var component = components[i];
            var fragment  = [UInt8]();
            
            fragment.append(UInt8(component & 0x7f));
            
            while component >= 0x80 {
                component = component >> 7;
                fragment.append(UInt8(component & 0x7f | 0x80));
            }
            
            value += fragment.reversed();
        }
        
        data += TagObjectIdentifier;
        data += encodeLength(value.count);
        data += value;
        
        return data;
    }
    
    func encodeSequence(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += TagSequence;
        data += encodeLength(bytes.count);
        data += bytes;
        
        return data;
    }
    
    func encodeSet(bytes: [UInt8]) -> [UInt8]
    {
        var data = [UInt8]();
        
        data += TagSet
        data += encodeLength(bytes.count);
        data += bytes;
        
        return data;
    }
    
    func encodePrintableString(_ value: String) -> [UInt8]
    {
        var data       = [UInt8]();
        let characters : [UInt8] = value.unicodeScalars.map { UInt8($0.value) }
        
        data += TagPrintableString;
        data += encodeLength(characters.count);
        data += characters;
        
        return data;
    }
    
    func encodeUTCTime(_ date: Date) -> [UInt8]
    {
        var data      = [UInt8]();
        let utcString = dateFormatter.string(from: date) + "Z";
        let utc       = utcString.unicodeScalars.map { UInt8($0.value) }
        
        data += TagUTCTime;
        data += encodeLength(utc.count);
        data += utc;
        
        return data;
    }
    
    func encodeUTF8String(_ value: String) -> [UInt8]
    {
        var data = [UInt8]();
        let utf8 = value.utf8;
        
        data += TagString;
        data += encodeLength(utf8.count);
        data += utf8;
        
        return data;
    }

}


// End of File
