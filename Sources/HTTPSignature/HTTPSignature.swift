// The Swift Programming Language
// https://docs.swift.org/swift-book

import Crypto
import Foundation
import SwiftASN1
import _CryptoExtras

/// Number of bytes prefixed to Curve25519 DER representation bytes to describe the curve.
let ecPemPrefix: Int = 12

/// Number of bytes for a Curve25519 DER representation.
let ecPemDataLen: Int = 32

/// SigningKey can be either a Curve25519 or RSA-2048 public key used to verify a signature from a request header.
struct SigningKey {
    let rsaPublicKey: _RSA.Signing.PublicKey?
    let ecPublicKey: Curve25519.Signing.PublicKey?
    let keyType: KeyTypes

    public init(pem: String) throws {
        let pemDoc = try PEMDocument.init(pemString: pem)
        if pemDoc.derBytes.count > ecPemPrefix + ecPemDataLen {
            let pubKey = try _RSA.Signing.PublicKey(pemRepresentation: pem)
            self.rsaPublicKey = pubKey
            self.ecPublicKey = nil
            self.keyType = .rsa2048
        } else {
            let ecKey = try Curve25519.Signing.PublicKey.init(rawRepresentation: pemDoc.derBytes[ecPemPrefix...])
            self.ecPublicKey = ecKey
            self.rsaPublicKey = nil
            self.keyType = .curve25519
        }
    }

}

enum KeyTypes {
    case rsa2048
    case curve25519
}
