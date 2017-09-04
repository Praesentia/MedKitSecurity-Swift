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
import Security.SecureTransport


class SSLContext2 {

    // MARK: - Properties
    //var      certificateAuthorities : [SecCertificate]?   { return getCertificateAuthorities() }
    weak var delegate               : SSLContextDelegate?
    var      peerTrust              : SecTrust?           { return getPeerTrust() }
    var      state                  : SSLSessionState     { return getSessionState() }

    // MARK: - Private Properties
    private var context: SSLContext!

    // MARK: - Initializers

    init?(_ protocolSide: SSLProtocolSide, _ connectionType: SSLConnectionType)
    {
        let context = SSLCreateContext(nil, protocolSide, connectionType)

        if let context = context {
            self.context = context

            let _ = SSLSetConnection(context, bridge(obj: self))
            let _ = SSLSetIOFuncs(context, readFunc, writeFunc)
        }
        else {
            return nil
        }
    }

    // MARK: - Configuration

    func setCertificate(_ chain: CFArray) -> OSStatus
    {
        return SSLSetCertificate(context, chain)
    }

    func setPeerDomainName(_ peerName: String) -> OSStatus
    {
        let utf8   = Data(peerName.utf8)
        var status : OSStatus = errSecSuccess

        utf8.withUnsafeBytes() {
            status = SSLSetPeerDomainName(context, $0, utf8.count)
        }

        return status
    }

    func setSessionConfig(_ config: CFString) -> OSStatus
    {
        return SSLSetSessionConfig(context, config)
    }

    func setSessionOption(_ option: SSLSessionOption, _ value: Bool) -> OSStatus
    {
        return SSLSetSessionOption(context, option, value)
    }

    // MARK: - State Management

    func close() -> OSStatus
    {
        return SSLClose(context)
    }

    func handshake() -> OSStatus
    {
        return SSLHandshake(context)
    }

    // MARK: - I/O

    func read(_ data: inout Data, _ dataLength: inout Int) -> OSStatus
    {
        var status: OSStatus = errSecSuccess

        data.withUnsafeMutableBytes() {
            status = SSLRead(context, $0, data.count, &dataLength)
        }
        return status
    }

    func write(_ data: Data, _ dataLength: inout Int) -> OSStatus
    {
        var status: OSStatus = errSecSuccess

        data.withUnsafeBytes() {
            status = SSLWrite(context, $0, data.count, &dataLength)
        }
        return status
    }

    // MARK: - Private

    private func getSessionState() -> SSLSessionState
    {
        var state: SSLSessionState = .idle

        let _ = SSLGetSessionState(context, &state)
        // TODO: status?

        return state
    }

    private func getPeerTrust() -> SecTrust?
    {
        var trust: SecTrust?

        let _ = SSLCopyPeerTrust(context, &trust)

        return trust
    }

}

/**
 SSL read callback.
 */
fileprivate func readFunc(_ connection: SSLConnectionRef, _ data: UnsafeMutableRawPointer, _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus
{
    let connection : SSLContext2 = bridge(ptr: connection)
    var status     : OSStatus    = errSecIO

    if let delegate = connection.delegate {
        let buffer = UnsafeMutableRawBufferPointer(start: data, count: dataLength.pointee)
        status = delegate.sslRead(connection, buffer, &dataLength.pointee)
    }

    return status
}

/**
 SSL write callback.
 */
fileprivate func writeFunc(_ connection: SSLConnectionRef, _ data: UnsafeRawPointer, _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus
{
    let connection : SSLContext2 = bridge(ptr: connection)
    var status     : OSStatus    = errSecIO

    if let delegate = connection.delegate {
        let buffer = Data(bytes: data, count: dataLength.pointee)
        status = delegate.sslWrite(connection, buffer, &dataLength.pointee)
    }

    return status
}


// End of File

