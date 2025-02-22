import { verifyCertificateVerify } from "../src/certificateverify.js";
import { CertificateVerify, createSignature } from "../src/certificateverify.js";
import { assertEquals, HexaDecimal, SignatureScheme, Handshake, safeuint8array, Uint16 } from "../src/dep.ts"
import { ClientHello } from "@tls/keyexchange"

Deno.test("CertificateVerify", () => {
   const certificateVerifyMsg = HexaDecimal.fromString(`0f 00 00 84 08 04 00 80 5a 74 7c
      5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
      b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
      86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
      be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
      5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
      3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3`).byte

   const certificateVerifyMsg_back = CertificateVerify.from(certificateVerifyMsg.slice(4));
   assertEquals(certificateVerifyMsg.slice(4).toString(), certificateVerifyMsg_back.toString())
})

export const clientHelloMsg = HexaDecimal.fromString(
   `01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
   ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
   02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
   00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
   12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
   00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
   3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
   af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
   02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
   02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`).byte

export const serverHelloMsg = HexaDecimal.fromString(
   `02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e
   6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2
   69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11
   20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69
   b1 b0 4e 75 1f 0f 00 2b 00 02 03 04`).byte

export const encryptedExtensionsMsg = HexaDecimal.fromString(`08 00 00 24 00 22 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
         00 02 40 01 00 00 00 00`).byte

export const certificateMsg = HexaDecimal.fromString(
   `0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
   01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
   86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
   72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
   0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
   03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
   0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
   82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
   d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
   1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
   4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
   80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
   ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
   01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
   03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
   01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
   72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
   e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
   51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
   c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
   1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
   96 12 29 ac 91 87 b4 2b 4d e1 00 00`).byte;

const certificateVerifyMsg = HexaDecimal.fromString(`0f 00 00 84 08 04 00 80 5a 74 7c
         5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
         b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
         86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
         be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
         5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
         3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3`).byte;

const n = HexaDecimal.fromString(`b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c
            0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab
            bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87
            a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f
            da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0
            3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e
            3f`).base64url;
const e = HexaDecimal.fromString(`01 00 01`).base64url;
const d = HexaDecimal.fromString(`04 de a7 05 d4 3a 6e a7 20 9d d8 07 21 11 a8 3c 81
            e3 22 a5 92 78 b3 34 80 64 1e af 7c 0a 69 85 b8 e3 1c 44 f6 de 62
            e1 b4 c2 30 9f 61 26 e7 7b 7c 41 e9 23 31 4b bf a3 88 13 05 dc 12
            17 f1 6c 81 9c e5 38 e9 22 f3 69 82 8d 0e 57 19 5d 8c 84 88 46 02
            07 b2 fa a7 26 bc f7 08 bb d7 db 7f 67 9f 89 34 92 fc 2a 62 2e 08
            97 0a ac 44 1c e4 e0 c3 08 8d f2 5a e6 79 23 3d f8 a3 bd a2 ff 99
            41`).base64url;
const p = HexaDecimal.fromString(`e4 35 fb 7c c8 37 37 75 6d ac ea 96 ab 7f 59 a2 cc 10 69 db
            7d eb 19 0e 17 e3 3a 53 2b 27 3f 30 a3 27 aa 0a aa bc 58 cd 67 46
            6a f9 84 5f ad c6 75 fe 09 4a f9 2c 4b d1 f2 c1 bc 33 dd 2e 05 15`).base64url;
const q = HexaDecimal.fromString(`ca bd 3b c0 e0 43 86 64 c8 d4 cc 9f 99 97 7a 94 d9 bb fe ad
            8e 43 87 0a ba e3 f7 eb 8b 4e 0e ee 8a f1 d9 b4 71 9b a6 19 6c f2
            cb ba ee eb f8 b3 49 0a fe 9e 9f fa 74 a8 8a a5 1f c6 45 62 93 03`).base64url;
const dp = HexaDecimal.fromString(`3f 57 34 5c 27 fe 1b 68 7e 6e 76 16 27 b7 8b 1b 82 64 33
            dd 76 0f a0 be a6 a6 ac f3 94 90 aa 1b 47 cd a4 86 9d 68 f5 84 dd
            5b 50 29 bd 32 09 3b 82 58 66 1f e7 15 02 5e 5d 70 a4 5a 08 d3 d3
            19`).base64url;
const dq = HexaDecimal.fromString(`18 3d a0 13 63 bd 2f 28 85 ca cb dc 99 64 bf 47 64 f1 51
            76 36 f8 64 01 28 6f 71 89 3c 52 cc fe 40 a6 c2 3d 0d 08 6b 47 c6
            fb 10 d8 fd 10 41 e0 4d ef 7e 9a 40 ce 95 7c 41 77 94 e1 04 12 d1
            39`).base64url;
const qi = HexaDecimal.fromString(`83 9c a9 a0 85 e4 28 6b 2c 90 e4 66 99 7a 2c 68 1f 21
            33 9a a3 47 78 14 e4 de c1 18 33 05 0e d5 0d d1 3c c0 38 04 8a 43
            c5 9b 2a cc 41 68 89 c0 37 66 5f e5 af a6 05 96 9f 8c 01 df a5 ca
            96 9d`).base64url;

const jwk = {
   kty: 'RSA', n, e, d, p, q, dp, dq, qi
}

var privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign'])

export const rsaKey = await crypto.subtle.generateKey(
   {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",     // SHA-1, SHA-256, SHA-384, or SHA-512
      publicExponent: new Uint8Array([1, 0, 1]), // 0x03 or 0x010001
      modulusLength: 1024, // 1024, 2048, or 4096
   },
   true,
   ["sign", "verify"],
)

//SignatureScheme.RSA_PKCS1_SHA256

const isValid = await verifyCertificateVerify(clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg, certificateVerifyMsg);

const signature = await createSignature(clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg, privateKey, { name: "RSA-PSS", saltLength: 32 });
const certificateVerifyMsg_0 = Handshake.fromCertificateVerify(safeuint8array(SignatureScheme.RSA_PSS_PSS_SHA256.byte, Uint16.fromValue(signature.length), signature));

const ch = ClientHello.from(clientHelloMsg); 

const isValid_0 = await verifyCertificateVerify(clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg, certificateVerifyMsg_0);



