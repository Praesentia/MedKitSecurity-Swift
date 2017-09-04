/*
 -----------------------------------------------------------------------------
 This source file is part of MedKitSecurity.
 
 Copyright 2016-2017 Jon Griffeth
 
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
import MedKitCore
import SecurityKit


/**
 Secure streaming port.
 */
public class PortSecureTLS: PortSecure, MedKitCore.PortDelegate, SSLContextDelegate {

    // MARK: - Properties
    public weak var delegate: MedKitCore.PortDelegate?
    public weak var policy  : PortSecurePolicy?
    
    // MARK: - Private Properties
    private var buffer  = Data(repeating: 0, count: 8192)
    private var context : SSLContext2!;
    private let input   = DataQueue()
    private let mode    : ProtocolMode
    private let port    : MedKitCore.Port
    
    // MARK: - Initializers
    
    public required init(port: MedKitCore.Port, mode: ProtocolMode)
    {
        self.port     = port
        self.mode     = mode
        port.delegate = self
    }
    
    // MARK: - Lifecycle
    
    public func shutdown(for reason: Error?)
    {
        port.shutdown(for: reason)
    }
    
    public func start()
    {
        port.start()
    }
    
    // MARK: - Output
    
    public func send(_ data: Data)
    {
        if context.state == .connected {
            var dataLength = Int(0)

            let status = context.write(data, &dataLength)
            switch status {
            case errSecSuccess :
                break

            default :
                close(for: NSError(osstatus: status))
            }
        }
    }
    
    // MARK: - Private

    /**
     Session handshake aborted.
     */
    private func aborted(for reason: Error?)
    {
        delegate?.portDidInitialize(self, with: reason)
        shutdown(for: reason)
    }

    /**
     Configure SSL session context.
     */
    private func configure() -> Error?
    {
        var status: OSStatus

        // create context
        context = SSLContext2(mode.protocolSide, .streamType)
        guard context != nil else { return MedKitError.failed }
        context.delegate = self

        // set general configuration
        status = context.setSessionConfig(kSSLSessionConfig_ATSv1)
        guard(status == errSecSuccess) else { return NSError(osstatus: status) }

        // set peer name
        if let peerName = policy?.portPeerName(self) {
            status = context.setPeerDomainName(peerName)
            guard status == errSecSuccess else { return NSError(osstatus: status) }
        }

        // set client-side options
        if mode == .client {
            status = context.setSessionOption(.breakOnServerAuth, true)
            guard status == errSecSuccess else { return NSError(osstatus: status) }
        }

        // set server-side options
        if mode == .server {
            if let credentials = policy?.portCredentials(self) as? PublicKeyCredentials {
                if let certificate = credentials.certificate as? X509 {
                    let (identity, error) = Keychain.main.instantiateIdentity(with: certificate.certificate)

                    if error == nil, let identity = identity {
                        let tail  = credentials.chain.map { ($0 as! X509).certificate }
                        var chain : [Any] = [identity]

                        chain.append(tail[0])
                        status = context.setCertificate(chain as CFArray)
                        guard status == errSecSuccess else { return NSError(osstatus: status) }
                    }
                }
            }
        }
        
        return nil
    }

    /**
     Close session.
     */
    private func close(for reason: Error?)
    {
        let _ = context.close()
        input.clear()
        shutdown(for: reason)
    }

    /**
     Handshake

     - Precondition:
         context != nil
         context.state == .idle || context.state == .handshake
     */
    private func handshake()
    {
        var ok = true

        while ok {
            let status = context.handshake()

            switch status {
            case errSecSuccess :
                ok = false
                delegate?.portDidInitialize(self, with: nil)

            case errSSLWouldBlock :
                ok = false

            case errSSLPeerAuthCompleted :
                if !verifyCredentials() {
                    ok = false
                    aborted(for: MedKitError.badCredentials)
                }

            default : // anything else is fatal
                ok = false
                aborted(for: NSError(osstatus: status))
            }
        }
    }

    /**
     Initialize context and begin handshake.

     - Precondition:
         context == nil
     */
    private func initialize()
    {
        let error = configure()
        
        if error == nil {
            handshake()
        }
        else {
            aborted(for: error)
        }
    }

    /**
     Read data from context.

     - Precondition:
         context.state == .connected
     */
    private func read()
    {
        var ok = true

        while ok {
            var dataLength = buffer.count
            let status     = context.read(&buffer, &dataLength)

            switch status {
            case errSecSuccess :
                delegate?.port(self, didReceive: buffer.subdata(in: 0..<dataLength))

            case errSSLWouldBlock :
                ok = false

            default : // anything else is fatal
                ok = false
                port.shutdown(for: NSError(osstatus: status))
            }
        }
    }

    /**
     */
    private func verifyCredentials() -> Bool
    {
        if let trust = context.peerTrust {

            var status: OSStatus
            var result: SecTrustResultType = .invalid

            // set anchor certificates
            let (anchorCertificates, error) = Keychain.main.findRootCertificates()
            guard error == nil else { return false }

            status = trust.setAnchorCertificates(anchorCertificates!)
            guard status == errSecSuccess else { return false }

            // evaluate trust
            status = trust.evaluate(&result)
            guard status == errSecSuccess else { return false }

            return result == .unspecified
        }

        return false
    }

    // MARK: - SSLContextDelegate
    
    /**
     Read
     */
    func sslRead(_ context: SSLContext2, _ data: UnsafeMutableRawBufferPointer, _ dataLength: inout Int) -> OSStatus
    {
        var status: OSStatus

        if !input.isEmpty {
            let count = min(input.count, UInt64(dataLength))
            let bytes  = input.read(count: Int(count))
            
            for i in 0..<bytes.count {
                data[i] = bytes[i]
            }

            if bytes.count == dataLength {
                status     = errSecSuccess
            }
            else {
                dataLength = bytes.count
                status     = errSSLWouldBlock
            }
        }
        else {
            dataLength = 0
            status     = errSSLWouldBlock
        }
        
        return status
    }

    /**
     Write
     */
    func sslWrite(_ context: SSLContext2, _ data: Data, _ dataLength: inout Int) -> OSStatus
    {
        port.send(data)
        dataLength = data.count
        return errSecSuccess
    }
    
    // MARK: - PortDelegate
    
    /**
     Port did close.
     */
    public func portDidClose(_ port: MedKitCore.Port, for reason: Error?)
    {
        let _ = context.close()
        input.clear()
        delegate?.portDidClose(self, for: reason)
    }
    
    /**
     Port did initialize.
     */
    public func portDidInitialize(_ port: MedKitCore.Port, with error: Error?)
    {
        if error == nil {
            initialize()
        }
        else {
            delegate?.portDidInitialize(self, with: error)
        }
    }
    
    /**
     Port did receive data.
     */
    public func port(_ port: MedKitCore.Port, didReceive data: Data)
    {
        input.append(data)

        switch context.state {
        case .idle :       // not expected here, but otherwise benign
            break

        case .handshake :  // handshake in progress
            handshake()

        case .aborted :    // TODO: when is this seen?
            aborted(for: nil)

        case .connected : // normal read state
            read()

        case .closed :    // spurious input
            input.clear()
        }
    }
    
}


// End of File
