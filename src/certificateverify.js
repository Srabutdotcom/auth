//@ts-self-types = "../type/certificateverify.d.ts"
import { Struct, Uint16, SignatureScheme, safeuint8array } from "./dep.ts";
import { BooleanPlus } from "./utils.js";
import { sha256, sha384, sha512 } from "./dep.ts"
import { Certificate } from "./certificate.js";

/**
 * {@link <CertificateVerify>} https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
 */
export class CertificateVerify extends Uint8Array {
   #algorithm
   #signature
   static sanitize(array) {
      try {
         const _algo = SignatureScheme.from(array);
         const lengthOf = Uint16.from(array.subarray(2)).value;
         if (array.length < 4 + lengthOf) return BooleanPlus.toFalse(Error(`the length of signature is less than expected`))
         return BooleanPlus.toTrue([array.slice(0, 4 + lengthOf)])
      } catch (error) {
         throw error
         //return BooleanPlus.toFalse(error)
      }
   }
   static from(array) { return new CertificateVerify(array) }
   constructor(...args) {
      args = (args[0] instanceof Uint8Array) ? CertificateVerify.sanitize(args[0]).data : args
      super(...args)
   }
   get algorithm() {
      this.#algorithm ||= SignatureScheme.from(this)
      return this.#algorithm;
   }
   get signature() {
      if (this.#signature) return this.#signature;
      const lengthOf = Uint16.from(this.subarray(2)).value;
      this.#signature ||= this.subarray(4, 4 + lengthOf);
      return this.#signature;
   }
}

/* export class CertificateVerify_0 extends Uint8Array {
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
} */

/* export class Signature extends Uint8Array {
   static sanitize(array) {
      try {
         const lengthOf = Uint16.from(array).value;
         if (array.length < 2 + lengthOf) return BooleanPlus.toFalse(Error(`the length of signature is less than expected`))
         return [array.slice(0, 2 + lengthOf)];
      } catch (error) {
         return BooleanPlus.toFalse(error)
      }
   }
   static from(array) { return new Signature(array) }
   constructor(...args) {
      args = (args[0] instanceof Uint8Array) ? CertificateVerify.sanitize(args[0]).data : args
      super(...args)
   }
}

export class Signature_0 extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      return new Signature(copy.subarray(2, 2 + lengthOf))
   }
   constructor(opaque) {
      super(0, 2 ** 16 - 1, opaque)
      this.opaque = opaque
   }
} */

export var leading = Uint8Array.of(
   //NOTE 64 space characters 
   32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
   //NOTE 'TLS 1.3, server CertificateVerify'
   84, 76, 83, 32, 49, 46, 51, 44, 32, 115, 101, 114, 118, 101, 114, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121,
   //NOTE single null char
   0
)

export async function createSignature(clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg, privateKey, algo) {

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
      privateKey,
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

export function hashFromAlgo(algo) {
   let sha
   const { hash, saltLength } = algo;
   if (hash) { sha = parseInt(hash.split("-")[1]); }
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

export async function verifyCertificateVerify(
   transcript, certificateVerifyMsg 
) {
   const { certificateMsg }  = transcript;
   
   const { signature, algorithm: { algo } } = CertificateVerify.from(certificateVerifyMsg.slice(4));
   const publicKey = await Certificate.from(certificateMsg.slice(4)).publicKey(algo.import);
   
   const hash = hashFromAlgo(algo.verify);

   const transcriptHash = hash
      .update(transcript.byte)
      .digest();

   const data = safeuint8array(
      leading,
      transcriptHash
   )

   const isTrue = await crypto.subtle.verify(
      algo.verify, //publicKey.algorithm,//
      publicKey, 
      signature, 
      data
   )

   transcript.insert(certificateVerifyMsg)

   return new BooleanPlus(isTrue, transcript)

   /**
    * RSA signatures MUST use an
      RSASSA-PSS algorithm, regardless of whether RSASSA-PKCS1-v1_5
      algorithms appear in "signature_algorithms"
      saltLength is determined by CertificateVerify.algorithm
   */

   /* The receiver of a CertificateVerify message MUST verify the signature
      field.  The verification process takes as input:

   -  The content covered by the digital signature

   -  The public key contained in the end-entity certificate found in
      the associated Certificate message

   -  The digital signature received in the signature field of the
      CertificateVerify message 
   */
}

export async function verifyCertificateVerify_0(
   clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg, certificateVerifyMsg
) {
   const { signature, algorithm: { algo } } = CertificateVerify.from(certificateVerifyMsg.slice(4));
   const publicKey = await Certificate.from(certificateMsg.slice(4)).publicKey(algo.import);

   const hash = hashFromAlgo(algo.verify);

   const transcriptHash = hash
      .update(safeuint8array(clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg))
      .digest();

   const data = safeuint8array(
      leading,
      transcriptHash
   )


   return await crypto.subtle.verify(
      algo.verify, //publicKey.algorithm,//
      publicKey, 
      signature, 
      data
   )
}