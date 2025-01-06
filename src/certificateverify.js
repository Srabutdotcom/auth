//@ts-self-types = "../type/certificateverify.d.ts"
import { HandshakeType, Struct, Uint16, Constrained, SignatureScheme } from "./dep.ts";
import { messageFromHandshake } from "./utils.js";

export class CertificateVerify extends Uint8Array {
   static fromHandshake(handshake) {
      return messageFromHandshake(handshake)
   }
   static from(array) {
      const copy = array.slice();
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
   get handshake(){ return HandshakeType.CERTIFICATE_VERIFY.handshake(this)}
   get record() { return ContentType.HANDSHAKE.tlsPlaintext(this.handshake) }
}

export class Signature extends Constrained {
   static from(array) {
      const copy = array.slice();
      const lengthOf = Uint16.from(copy).value;
      return new Signature(copy.subarray(2, 2 + lengthOf))
   }
   constructor(opaque) {
      super(0, 2 ** 16 - 1, opaque)
      this.opaque = opaque
   }
}