// The Swift Programming Language
// https://docs.swift.org/swift-book

import Crypto
import Foundation
import SwiftASN1
import _CryptoExtras

struct SigningKey {
    let rsaPublicKey: _RSA.Signing.PublicKey?
    let ecPublicKey: Curve25519.Signing.PublicKey?

    public init(rsaPem: String) throws {
        let pubKey = try _RSA.Signing.PublicKey(pemRepresentation: rsaPem)
        self.rsaPublicKey = pubKey
        self.ecPublicKey = nil
    }

    public init(ecPem: String) throws {
        let pemDoc = try PEMDocument.init(pemString: ecPem)
        let ecKey = try Curve25519.Signing.PublicKey.init(rawRepresentation: pemDoc.derBytes[12...])
        self.ecPublicKey = ecKey
        self.rsaPublicKey = nil
    }
}
