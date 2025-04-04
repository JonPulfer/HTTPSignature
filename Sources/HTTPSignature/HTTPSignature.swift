// The Swift Programming Language
// https://docs.swift.org/swift-book

import Crypto
import Foundation
import SwiftASN1
import _CryptoExtras

/// A SignedRequestVerifier is used to verify the signature of a signed request.
public struct SignedRequestVerifier {
    let signingPubKey: SigningPublicKey

    public init(publicKeyPem: String) throws {
        signingPubKey = try SigningPublicKey.init(pem: publicKeyPem)
    }

    public func isValidRequestSignature(request: URLRequest) throws -> Bool {
        return try signingPubKey.isValidRequestSignature(request: request)
    }
}

/// a SignedRequestSigner is able to sign a request using the provided private key.
public struct SignedRequestSigner {
    let signingPrivateKey: SigningPrivateKey

    public init(privateKeyPem: String) throws {
        signingPrivateKey = try SigningPrivateKey.init(pem: privateKeyPem)
    }

    // TODO(JP): implement request signing.
}

/// Number of bytes prefixed to Curve25519 DER representation bytes to describe the curve.
let ecPemPrefix: Int = 12

/// Number of bytes for a Curve25519 DER representation.
let ecPemDataLen: Int = 32

/// SigningPublicKey used to verify a signature from a request header.
struct SigningPublicKey {
    let rsaPublicKey: _RSA.Signing.PublicKey?
    let ecPublicKey: Curve25519.Signing.PublicKey?
    let keyType: KeyTypes

    /// Supports the following PEM encoded public key types: -
    ///
    /// - Curve25519
    /// - RSA 2048bit
    init(pem: String) throws {
        let pemDoc = try PEMDocument.init(pemString: pem)
        if pemDoc.derBytes.count > ecPemPrefix + ecPemDataLen {
            let rsaKey = try _RSA.Signing.PublicKey(pemRepresentation: pem)
            rsaPublicKey = rsaKey
            ecPublicKey = nil
            keyType = .rsa2048
        } else {
            let ecKey = try Curve25519.Signing.PublicKey.init(
                rawRepresentation:
                    pemDoc.derBytes[ecPemPrefix...]
            )
            ecPublicKey = ecKey
            rsaPublicKey = nil
            keyType = .curve25519
        }
    }

    /// Review the request and extract the signed fields and the signature to verify the signature using the
    /// `SigningPublicKey`. Only returns valid when there are no errors encountered and the signature is valid.
    ///
    /// - Returns: boolean indicating whether the signature is valid.
    func isValidRequestSignature(request: URLRequest) throws -> Bool {

        let requestHeaders = request.allHTTPHeaderFields ?? [:]
        let signatureData = try SignatureData(fromHeaders: requestHeaders)

        switch keyType {
        case .curve25519:
            if let signturareValid = ecPublicKey?.isValidSignature(
                signatureData.signature,
                for: signatureData.signedData(request: request)
            ) {
                return signturareValid
            }
        case .rsa2048:
            if let signatureValid = rsaPublicKey?.isValidSignature(
                _RSA.Signing.RSASignature(rawRepresentation: signatureData.signature),
                for: signatureData.signedData(request: request)
            ) {
                return signatureValid
            }
        }

        return false
    }

}

struct SigningPrivateKey {
    let rsaPrivateKey: _RSA.Signing.PrivateKey?
    let ecPrivateKey: Curve25519.Signing.PrivateKey?
    let keyType: KeyTypes

    init(pem: String) throws {
        let pemDoc = try PEMDocument.init(pemString: pem)
        if pemDoc.derBytes.count > ecPemPrefix + ecPemDataLen {
            let rsaKey = try _RSA.Signing.PrivateKey(pemRepresentation: pem)
            rsaPrivateKey = rsaKey
            ecPrivateKey = nil
            keyType = .rsa2048
        } else {
            let ecKey = try Curve25519.Signing.PrivateKey.init(
                rawRepresentation:
                    pemDoc.derBytes[ecPemPrefix...]
            )
            ecPrivateKey = ecKey
            rsaPrivateKey = nil
            keyType = .curve25519
        }
    }
}

enum KeyTypes {
    case rsa2048
    case curve25519
}

let signatureHeaderKey = "Signature"
let signatureKeyIdField = "keyId"
let signatureHeadersField = "headers"
let signatureSignatureField = "signature"

struct SignatureData {
    let keyId: String
    let headers: [String]
    let signatureValue: String
    var signature: UnsafeBufferPointer<UInt8> {
        get {
            var sig = signatureValue
            return sig.withUTF8 { buffer in
                return buffer
            }
        }
    }

    init(fromHeaders: [String: String]) throws {
        guard let signatureFromHeader = fromHeaders[signatureHeaderKey]
        else {
            throw SignatureErrors.headerNotFound
        }
        var signatureParts: [String: String] = [:]
        let _ = signatureFromHeader.split(separator: ",").map() {
            let elemParts = $0.split(separator: "=")
            if elemParts.count == 2 {
                signatureParts[String(elemParts[0])] = String(elemParts[1])
            }
        }

        guard let headerValue = signatureParts[signatureHeadersField]
        else {
            throw SignatureErrors.headersFieldMissing
        }
        var foundHeaders: [String] = []
        for header in headerValue.split(separator: " ") {
            var value = String(header)
            value.replace("\"", with: "")
            foundHeaders.append(value)
        }
        headers = foundHeaders

        guard var signatureFieldValue = signatureParts[signatureSignatureField]
        else {
            throw SignatureErrors.signatureFieldMissing
        }
        signatureFieldValue.replace("\"", with: "")
        signatureValue = signatureFieldValue

        guard var keyIdValue = signatureParts[signatureKeyIdField]
        else {
            throw SignatureErrors.keyIdFieldMissing
        }
        keyIdValue.replace("\"", with: "")
        keyId = keyIdValue
    }

    func signedData(request: URLRequest) -> UnsafeBufferPointer<UInt8> {
        var plaintext: String = ""
        for header in headers {
            plaintext += (request.allHTTPHeaderFields?[header] ?? "")
        }
        plaintext.replace("\"", with: "")
        return plaintext.withUTF8 { buffer in
            return buffer
        }
    }
}

public enum SignatureErrors: Error {
    case headerNotFound
    case headerIncomplete
    case headersFieldMissing
    case signatureFieldMissing
    case keyIdFieldMissing
}
