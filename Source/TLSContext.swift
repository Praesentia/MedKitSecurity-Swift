/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.

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
import SecurityKit


/**
 TLS Context

 TLS Adapter to SSLContext.
 */
class TLSContext : TLS {

    // MARK: - Properties
    weak var delegate  : TLSDelegate?
    var      state     : TLSState     { return getSessionState() }
    weak var stream    : TLSDataStream?
    var      peerTrust : SecTrust?    { return getPeerTrust() }

    // MARK: - Private Properties
    private var context      : SSLContext
    private var protocolSide : SSLProtocolSide;

    // MARK: - Initializers

    init(_ protocolSide: SSLProtocolSide, _ connectionType: SSLConnectionType)
    {
        self.context      = SSLCreateContext(nil, protocolSide, connectionType)!
        self.protocolSide = protocolSide;

        let connection = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        let _          = SSLSetConnection(context, connection)
        let _          = SSLSetIOFuncs(context, readFunc, writeFunc)
    }

    // MARK: - State Management

    func close() -> Error?
    {
        let status = SSLClose(context)
        return SecurityKitError(from: status)
    }

    func handshake() -> Error?
    {
        var status : OSStatus = errSecSuccess
        var ok     = true

        if state == .idle {
            status = configure();
            if status != errSecSuccess {
                ok = false
            }
        }

        while ok {
            status = SSLHandshake(context)

            switch status {
            case errSSLPeerAuthCompleted :
                let error = delegate?.tlsPeerAuthenticationComplete(self) ?? nil // TODO
                if error != nil {
                    return error
                }

            default :
                return SecurityKitError(from: status)
            }
        }

        return SecurityKitError(from: status)
    }

    // MARK: - Private

    /**
     Configure TLS session.
     */
    private func configure() -> OSStatus
    {
        var status: OSStatus = errSecSuccess

        // set general configuration
        status = setSessionConfig(kSSLSessionConfig_ATSv1)
        guard status == errSecSuccess else { return status }

        // set peer name
        if let peerName = delegate?.tlsPeerName(self) {
            status = setPeerDomainName(peerName)
            guard status == errSecSuccess else { return status }
        }

        // set client-side options
        if protocolSide == .clientSide {
            status = setSessionOption(.breakOnServerAuth, true)
            guard status == errSecSuccess else { return status }
        }

        // set server-side options
        if protocolSide == .serverSide {
            if let credentials = delegate?.tlsCredentials(self) {
                status = setCredentials(credentials)
                guard status == errSecSuccess else { return status }
            }
        }

        return status
    }

    private func setCredentials(_ credentials: PublicKeyCredentials) -> OSStatus
    {
        var status: OSStatus = errSecSuccess

        if let certificate = credentials.certificate as? X509 {
            var identity: SecIdentity?
            var error   : Error?

            (identity, error) = Keychain.main.instantiateIdentity(with: certificate.certificate)

            if error == nil, let identity = identity {
                let tail  = credentials.chain.map { ($0 as! X509).certificate }
                var chain : [Any] = [identity]
                chain.append(tail[0])
                status = SSLSetCertificate(context, chain as CFArray)
            }
        }
        
        return status
    }

    private func setPeerDomainName(_ peerName: String) -> OSStatus
    {
        let utf8   = Data(peerName.utf8)
        var status : OSStatus = errSecSuccess

        utf8.withUnsafeBytes() {
            status = SSLSetPeerDomainName(context, $0, utf8.count)
        }

        return status
    }

    private func setSessionConfig(_ config: CFString) -> OSStatus
    {
        return SSLSetSessionConfig(context, config)
    }

    private func setSessionOption(_ option: SSLSessionOption, _ value: Bool) -> OSStatus
    {
        return SSLSetSessionOption(context, option, value)
    }

    // MARK: - I/O

    func read(_ data: inout Data, _ dataLength: inout Int) -> Error?
    {
        var status: OSStatus = errSecSuccess

        data.withUnsafeMutableBytes() {
            status = SSLRead(context, $0, data.count, &dataLength)
        }
        return SecurityKitError(from: status)
    }

    func write(_ data: Data, _ dataLength: inout Int) -> Error?
    {
        var status: OSStatus = errSecSuccess

        data.withUnsafeBytes() {
            status = SSLWrite(context, $0, data.count, &dataLength)
        }
        return SecurityKitError(from: status)
    }

    // MARK: - Private

    private func getSessionState() -> TLSState
    {
        var stateSSL: SSLSessionState = .idle
        var stateTLS: TLSState        = .idle

        let status = SSLGetSessionState(context, &stateSSL)
        if status == errSecSuccess {
            switch stateSSL {
            case .idle :
                stateTLS = .idle

            case .handshake :
                stateTLS = .handshake

            case .closed :
                stateTLS = .closed

            case .connected :
                stateTLS = .connected

            case .aborted :
                stateTLS = .aborted
            }
        }

        return stateTLS
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
    let connection : TLSContext = Unmanaged<TLSContext>.fromOpaque(connection).takeUnretainedValue()
    var status     : OSStatus   = errSecIO

    if let stream = connection.stream {
        let buffer = UnsafeMutableRawBufferPointer(start: data, count: dataLength.pointee)
        var error  : Error?

        error  = stream.tlsRead(connection, buffer, &dataLength.pointee)
        status = SecurityKitError.osstatus(from: error as? SecurityKitError)
    }

    return status
}

/**
 SSL write callback.
 */
fileprivate func writeFunc(_ connection: SSLConnectionRef, _ data: UnsafeRawPointer, _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus
{
    let connection : TLSContext = Unmanaged<TLSContext>.fromOpaque(connection).takeUnretainedValue()
    var status     : OSStatus   = errSecIO

    if let stream = connection.stream {
        let buffer = Data(bytes: data, count: dataLength.pointee)
        var error  : Error?

        error  = stream.tlsWrite(connection, buffer, &dataLength.pointee)
        status = SecurityKitError.osstatus(from: error as? SecurityKitError)
    }

    return status
}


// End of File

