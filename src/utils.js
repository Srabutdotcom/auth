import { Certificate } from "./certificate.js";
import { CertificateVerify } from "./certificateverify.js";
import { HandshakeType, Uint24 } from "./dep.ts";
import { Finished } from "./finished.js";

export function messageFromHandshake(handshake) {
   const copy = Uint8Array.from(handshake);
   const type = HandshakeType.fromValue(copy.at(0));
   const lengthOf = Uint24.from(copy.subarray(1)).value;
   const message = copy.subarray(4, lengthOf + 4)
   switch (type) {
      case HandshakeType.CERTIFICATE_VERIFY: return CertificateVerify.from(message).handshake
      case HandshakeType.CERTIFICATE: return Certificate.from(message).handshake
      case HandshakeType.FINISHED: return Finished.from(message).handshake
   }
}