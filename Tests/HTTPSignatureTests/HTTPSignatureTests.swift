import Foundation
import Testing

@testable import HTTPSignature

@Suite class KeyHandlingTests {
    let exampleRSAPubKey = """
            -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtV8LJAscsGgAgtUsR1Tx
        0rcgqw8178DKu67F76dmWVQB1MLdDmyrAZv6XNrpqikMaZfjzdUERn14phBtPw+Z
        RFl7IUFyOYWUqOLJKN1d7YKK1cMg2fQEndL6kBg6sB/Ipp1YNwr/H82OsbriAznu
        n/q5OgMAZ3E0zu0nIwonNykI5NrE+yoe6KSa3Cy4QWpqTZJ1BeW29ZsJUzmM4hfE
        s3M/hRmh44o8NJ/9hY9UsoItMXrV4C76o25DG1mOsR/GqpMVXVBQzxez7GS2Yo+6
        AlMsxgaoPbMrVe5o2fbnhT7yBrdAnt0XFaofxiSau4n9xfjRmB2edIuevh+kfGpR
        aQIDAQAB
        -----END PUBLIC KEY-----
        """

    // Valid Curve25519 key details verified by openssl.
    let privateKeyBase64 = "sffPc3mtiJDKdGkN7TiascPiMeXm7UZqfXdBlYG7iyc="
    let examplePublicKey =
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAtV5dzF+zZV9Yup+riEAqaCNol/JumbAPjrT6CkEdpGg=\n-----END PUBLIC KEY-----\n"

    @Test func CanInitSigningKeyFromRSAPubKey() throws {
        let signKey = try SigningPublicKey.init(pem: exampleRSAPubKey)
        #expect(signKey.rsaPublicKey != nil)
        #expect(signKey.keyType == .rsa2048)
        #expect(signKey.rsaPublicKey!.keySizeInBits == 2048)
    }

    @Test func CanInitSigningKeyFromECPubKey() throws {
        let signKey = try SigningPublicKey.init(pem: examplePublicKey)
        #expect(signKey.ecPublicKey != nil)
        #expect(signKey.keyType == .curve25519)
        #expect(signKey.ecPublicKey!.rawRepresentation.count == 32)
    }

    @Test(
        "Expect error to be thrown when provided pem is not EC PubKey",
        arguments: [
            "some random string",
            """
            -----BEGIN PUBLIC KEY-----
            some stuff
            -----END PUBLIC KEY-----
            """,
        ]
    )
    func cannotInitECPubKeyWithBadData(badInput: String) throws {
        #expect(throws: (any Error).self) {
            try SigningPublicKey.init(pem: badInput)
        }
    }

}

@Suite class SignatureDataTests {

    @Test func SignatureDataInitialisesCorrectly() throws {
        let exampleSignatureHeader =
            #"keyId="https://my-example.com/actor#main-key",headers="(request-target)"#
            + #" host date digest",signature="some signature""#
        let signatureData = try SignatureData(fromHeaders: ["Signature": exampleSignatureHeader])
        #expect(signatureData.headers.count == 4)
        #expect(signatureData.headers.contains("(request-target)") == true)
        #expect(signatureData.headers.contains("host") == true)
        #expect(signatureData.headers.contains("date") == true)
        #expect(signatureData.headers.contains("digest") == true)
        #expect(signatureData.keyId == "https://my-example.com/actor#main-key")
        #expect(signatureData.signatureValue == "some signature")

    }
}
