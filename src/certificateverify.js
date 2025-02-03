//@ts-self-types = "../type/certificateverify.d.ts"
import { HandshakeType, Struct, Uint16, Constrained, SignatureScheme, Handshake } from "./dep.ts";
import { messageFromHandshake } from "./utils.js";
import { sha256, sha384, sha512 } from "./dep.ts"

export class CertificateVerify extends Uint8Array {
   static fromHandshake(handshake) {
      return messageFromHandshake(handshake)
   }
   static from(array) {
      const copy = Uint8Array.from(array);
      const algorithm = SignatureScheme.from(copy.subarray());
      const signature = Signature.from(copy.subarray(2))
      return new CertificateVerify(algorithm, signature)
   }
   constructor(algorithm, signature) {
      const struct = new Struct(
         algorithm.Uint16,
         signature
      )
      super(struct);
      this.algorithm = algorithm;
      this.signature = signature
   }
   get handshake() { return new Handshake(HandshakeType.CERTIFICATE_VERIFY, this) }
   get record() { return this.handshake.record }
}

export class Signature extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      return new Signature(copy.subarray(2, 2 + lengthOf))
   }
   constructor(opaque) {
      super(0, 2 ** 16 - 1, opaque)
      this.opaque = opaque
   }
}

export async function signatureFrom(clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg, RSAprivateKey, algo) {
   const leading = Uint8Array.of(
      //NOTE 64 space characters 
      32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
      //NOTE 'TLS 1.3, server CertificateVerify'
      84, 76, 83, 32, 49, 46, 51, 44, 32, 115, 101, 114, 118, 101, 114, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121,
      //NOTE single null char
      0
   )

   const hash = hashFromAlgo(algo)

   const transcriptHash = hash
      .update(clientHelloMsg)
      .update(serverHelloMsg)
      .update(encryptedExtensionsMsg)
      .update(certificateMsg)
      .digest();

   const data = Struct.createFrom(
      leading,
      transcriptHash
   )

   const signBuffer = await crypto.subtle.sign(
      algo,
      RSAprivateKey,
      data
   )

   /* const verify = await crypto.subtle.verify(
         {
            name: "RSA-PSS",//'RSASSA-PKCS1-v1_5',
            saltLength: 256 / 8
         },
         RSAPublicKey, //rsapublickey in Certificate
         sign,
         data
   ) */
   return new Uint8Array(signBuffer)
}

function hashFromAlgo(algo) {
   let sha
   const { _hash, saltLength } = algo;
   //if (hash) { sha = parseInt(hash.split("-")[1]); }
   if (saltLength) { sha = saltLength * 8 }
   else { sha = 256 };
   switch (sha) {
      case 384: return sha384.create();
      case 512: return sha512.create();
      case 256:
      default:
         return sha256.create();
   }
}