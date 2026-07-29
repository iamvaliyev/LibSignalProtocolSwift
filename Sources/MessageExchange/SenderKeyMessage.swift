//
//  SenderKeyMessage.swift
//  SignalProtocolSwift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
import Curve25519

/**
 A sender key message is used to send an encrypted message in an existing group session.
 
 Dart (libsignal_protocol_dart) serializes SenderKeyMessages as:
   [1 version byte] + [protobuf bytes] + [64 signature bytes]
 and signs over [version_byte + protobuf].
 
 The original Swift library serializes as:
   [protobuf bytes] + [64 signature bytes]
 and verifies over [protobuf] only.
 
 This version is patched to be compatible with the Dart format.
 */
public struct SenderKeyMessage {

    /// The id of the key that was used
    let keyId: UInt32

    /// The iteration of the chain key
    let iteration: UInt32

    /// The encrypted ciphertext
    let cipherText: Data

    /// The signature of the message
    var signature: Data
    
    /// The exact protobuf data from the parsed message (to avoid re-serialization differences)
    var serializedProtobuf: Data?
    
    /// The version byte from the Dart-serialized message (if present)
    var versionByte: UInt8?

    /**
     Return the message serialized 
    */
    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .senderKey, data: try self.protoData())
    }

    /**
     Create a `SenderKeyMessage` from the components.
     - parameter keyId: The id of the key that was used
     - parameter iteration: The iteration of the chain key
     - parameter cipherText: The encrypted ciphertext
     - parameter signatureKey: The key used for the message signature
     - throws: `SignalError` errors
    */
    init(keyId: UInt32, iteration: UInt32, cipherText: Data, signatureKey: PrivateKey) throws {
        self.keyId = keyId
        self.iteration = iteration
        self.cipherText = cipherText
        self.versionByte = nil
        self.serializedProtobuf = nil
        // Empty signature for serialization
        self.signature = Data()
        let data = try self.protoData()
        self.signature = try signatureKey.sign(message: data)
    }

    /**
     Verify that the signature matches the message.
     Supports both Dart format (version byte included in signed content)
     and legacy Swift format (no version byte).
     
     - parameter signatureKey: The key used to verify the message
     - returns: `True`, if the signature matches
     - throws: `SignalError` of type `invalidProtoBuf`
    */
    func verify(signatureKey: PublicKey) throws -> Bool {
        guard signature.count == Curve25519.signatureLength else {
            return false
        }
        
        // Get just the protobuf data (without signature)
        // Prefer exactly what we parsed (if available) to avoid non-deterministic serialization issues
        let protobufData: Data
        if let originalProtobuf = self.serializedProtobuf {
            protobufData = originalProtobuf
        } else {
            do {
                protobufData = try protoObject.serializedData()
            } catch {
                throw SignalError(.invalidProtoBuf, "Could not serialize for verification: \(error)")
            }
        }
        
        // If we have a version byte (Dart format), verify over [version + protobuf]
        if let vByte = versionByte {
            let signedContent = Data([vByte]) + protobufData
            if signatureKey.verify(signature: signature, for: signedContent) {
                return true
            }
        }
        
        // Fallback: try legacy Swift format (verify over protobuf only)
        return signatureKey.verify(signature: signature, for: protobufData)
    }
}


extension SenderKeyMessage: ProtocolBufferEquivalent {

    /// Convert the sender key message to a ProtoBuf object
    var protoObject: Signal_SenderKeyMessage {
        return Signal_SenderKeyMessage.with {
            $0.id = self.keyId
            $0.iteration = self.iteration
            $0.ciphertext = Data(self.cipherText)
        }
    }

    /**
     Create a sender key message from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` errors
     */
    init(from object: Signal_SenderKeyMessage) throws {
        guard object.hasID, object.hasIteration, object.hasCiphertext else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderKeyMessage object")
        }
        self.keyId = object.id
        self.iteration = object.iteration
        self.cipherText = object.ciphertext
        self.signature = Data()
        self.versionByte = nil
        self.serializedProtobuf = nil
    }

}

extension SenderKeyMessage: ProtocolBufferSerializable {

    /**
     Serialize the message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public func protoData() throws -> Data {
        do {
            return try protoObject.serializedData() + signature
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SenderKeyMessage: \(error)")
        }
    }

    /**
     Create a sender key message from serialized data.
     Supports both Dart format: [version_byte][protobuf][signature]
     and legacy Swift format: [protobuf][signature]
     
     - parameter data: The serialized data
     - throws: `SignalError` errors
     */
    public init(from data: Data) throws {
        guard data.count > Curve25519.signatureLength else {
            throw SignalError(.invalidProtoBuf, "Too few bytes in data for SenderKeyMessage")
        }
        
        // Try Dart format first: [1 version byte] + [protobuf] + [64 signature bytes]
        // Dart version byte encodes high nibble = 3 (currentVersion)
        let firstByte = data[data.startIndex]
        let highBits = Int(firstByte) >> 4
        
        if highBits == 3 && data.count > 1 + Curve25519.signatureLength {
            let withoutVersion = data[(data.startIndex + 1)...]
            let protobufLength = withoutVersion.count - Curve25519.signatureLength
            if protobufLength > 0 {
                let protobufData = Data(withoutVersion[withoutVersion.startIndex..<(withoutVersion.startIndex + protobufLength)])
                let signatureData = Data(withoutVersion[(withoutVersion.startIndex + protobufLength)...])
                
                if let object = try? Signal_SenderKeyMessage(serializedData: protobufData),
                   object.hasID, object.hasIteration, object.hasCiphertext {
                    try self.init(from: object)
                    self.signature = signatureData
                    self.versionByte = firstByte
                    self.serializedProtobuf = protobufData
                    return
                }
            }
        }
        
        // Fallback: legacy Swift format [protobuf][signature]
        let length = data.count - Curve25519.signatureLength
        guard length > 1 else {
            throw SignalError(.invalidProtoBuf, "Too few bytes in data for SenderKeyMessage")
        }
        let content = Data(data[data.startIndex..<(data.startIndex + length)])
        let signature = Data(data[(data.startIndex + length)...])
        let object: Signal_SenderKeyMessage
        do {
            object = try Signal_SenderKeyMessage(serializedData: content)
        } catch {
           throw SignalError(.invalidProtoBuf, "Could not create sender key message object: \(error)")
        }
        try self.init(from: object)
        self.signature = signature
        self.versionByte = nil
        self.serializedProtobuf = content
    }
}
