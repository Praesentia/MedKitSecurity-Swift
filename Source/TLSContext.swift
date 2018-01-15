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
import Security.SecureTransport
import SecurityKit


/**
 TLS Context

 TLS Adapter to SSLContext.
 */
class TLSContext : TLS {

    // MARK: - Properties
    weak var delegate : TLSDelegate?
    let      mode     : TLSMode
    var      state    : TLSState { return getSessionState() }
    weak var stream   : TLSDataStream?

    // MARK: - Private Properties
    private var context   : SSLContext
    private var peerTrust : SecTrust? { return getPeerTrust() }

    // MARK: - Initializers

    /**
     Initializer

     - Parameters:
         - mode: The TLS mode indicating whether this is a client or server
                 side connection.
     */
    init(mode: TLSMode)
    {
        self.context = SSLCreateContext(nil, mode.protocolSide, .streamType)!
        self.mode    = mode
    }

    // MARK: - Session Management

    /**
     Handshake

     Continue the TLS handshake.
     */
    func handshake() -> Error?
    {
        let status = handshakeP();
        return SecurityKitError(from: status)
    }

    /**
     Start session.

     Configures the session context and initiates the TLS handshake.
     */
    func start() -> Error?
    {
        var status: OSStatus

        status = configure();
        if status == errSecSuccess {
            status = handshakeP();
        }

        return SecurityKitError(from: status)
    }

    /**
     Shutdown session.

     Initiates a graceful shutdown of the session.
     */
    func shutdown() -> Error?
    {
        let status = SSLClose(context)
        return SecurityKitError(from: status)
    }

    // MARK: - Private

    /**
     Configure TLS session context.
     */
    private func configure() -> OSStatus
    {
        let connection = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        var status : OSStatus = errSecSuccess

        status = SSLSetConnection(context, connection)
        guard status == errSecSuccess else { return status }

        status = SSLSetIOFuncs(context, readFunc, writeFunc)
        guard status == errSecSuccess else { return status }

        // set general configuration
        status = setSessionConfig(kSSLSessionConfig_ATSv1)
        guard status == errSecSuccess else { return status }

        // set peer name
        if let peerName = delegate?.tlsPeerName(self) {
            status = setPeerName(peerName)
            guard status == errSecSuccess else { return status }
        }

        // set client-side options
        if mode == .client {
            status = setSessionOption(.breakOnServerAuth, true)
            guard status == errSecSuccess else { return status }
        }

        // set server-side options
        if mode == .server {
            if let credentials = delegate?.tlsCredentials(self) {
                status = setCredentials(credentials)
                guard status == errSecSuccess else { return status }
            }
        }

        return status
    }

    /**
     Initiate or otherwise continue the TLS handshake.

     - Returns:
         - errSecSuccess:
             Indicates that the handshake completed successfully.
         - errSSLClosedAbort:
             Indicates that the handshake has failed.
         - errSSLWouldBlock:
             Indicates that the handshake should be continued when additional
             data is available for reading.
     */
    private func handshakeP() -> OSStatus
    {
        var status : OSStatus = errSecSuccess
        var ok     = true

        while ok {
            status = SSLHandshake(context)
            switch status {
            case errSSLPeerAuthCompleted :
                let error = delegate?.tlsPeerAuthenticationComplete(self) ?? nil // TODO
                if error != nil {
                    status = errSSLClosedAbort
                    ok     = false
                }

            default :
                ok = false
            }
        }

        return status
    }

    /**
     Set credentials.
     */
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

    /**
     Set peer name.
     */
    private func setPeerName(_ peerName: String) -> OSStatus
    {
        let utf8   = Data(peerName.utf8)
        var status : OSStatus = errSecSuccess

        utf8.withUnsafeBytes() {
            status = SSLSetPeerDomainName(context, $0, utf8.count)
        }

        return status
    }

    /**
     Set session configuration.
     */
    private func setSessionConfig(_ config: CFString) -> OSStatus
    {
        return SSLSetSessionConfig(context, config)
    }

    /**
     Set session option.
     */
    private func setSessionOption(_ option: SSLSessionOption, _ value: Bool) -> OSStatus
    {
        return SSLSetSessionOption(context, option, value)
    }

    // MARK: - I/O

    /**
     Read data.
     */
    func read(_ data: inout Data, _ dataLength: inout Int) -> Error?
    {
        var status: OSStatus = errSecSuccess

        data.withUnsafeMutableBytes() {
            status = SSLRead(context, $0, data.count, &dataLength)
        }

        return SecurityKitError(from: status)
    }

    /**
     Write data.
     */
    func write(_ data: Data, _ dataLength: inout Int) -> Error?
    {
        var status: OSStatus = errSecSuccess

        data.withUnsafeBytes() {
            status = SSLWrite(context, $0, data.count, &dataLength)
        }

        return SecurityKitError(from: status)
    }

    // MARK: - Private

    /**
     Get session state.

     Maps the context's SSLSessionState to the TLSState.
     */
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
    let context : TLSContext = Unmanaged<TLSContext>.fromOpaque(connection).takeUnretainedValue()
    var status  : OSStatus   = errSSLClosedAbort

    if let stream = context.stream {
        var input  : Data?
        var error  : Error?

        (input, error) = stream.tlsRead(context, dataLength.pointee)
        if error == nil, let input = input {
            let buffer = UnsafeMutableRawBufferPointer(start: data, count: dataLength.pointee)
            let bytes  = [UInt8](input)

            for i in 0..<bytes.count {
                buffer[i] = bytes[i]
            }

            dataLength.pointee = bytes.count
        }
        else {
            dataLength.pointee = 0
        }

        status = SecurityKitError.osstatus(from: error as? SecurityKitError)
    }

    return status
}

/**
 SSL write callback.
 */
fileprivate func writeFunc(_ connection: SSLConnectionRef, _ data: UnsafeRawPointer, _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus
{
    let context : TLSContext = Unmanaged<TLSContext>.fromOpaque(connection).takeUnretainedValue()
    var status  : OSStatus   = errSSLClosedAbort

    if let stream = context.stream {
        let output = Data(bytes: data, count: dataLength.pointee)
        var count  : Int?
        var error  : Error?

        (count, error) = stream.tlsWrite(context, output)
        if error == nil, let count = count {
            dataLength.pointee = count
        }
        else {
            dataLength.pointee = 0
        }

        status = SecurityKitError.osstatus(from: error as? SecurityKitError)
    }

    return status
}


// End of File

