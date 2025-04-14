//@ts-self-types="../type/finished.d.ts"
import { unity } from "./dep.ts";
import { sha256, sha384 } from "./dep.ts"

export class Finished extends Uint8Array {
   static from(...args){return new Finished(...args)}
   constructor(...args){
      super(...args)
   }
}

/* export class Finished_0 extends Uint8Array {
   static fromHandshake(handshake) {
      return messageFromHandshake(handshake)
   }
   static from(array) {
      const copy = Uint8Array.from(array)
      return new Finished(copy)
   }
   constructor(verify_data) {
      super(verify_data);
      this.verify_data = verify_data
   }
   get handshake() { return new Handshake(HandshakeType.FINISHED, this) }
   get record() { return this.handshake.record }
} */

export async function finished(finishedKey, sha = 256, ...messages) {
   //const finishedKey = hkdfExpandLabel(serverHS_secret, 'finished', new Uint8Array, 32);
   const finishedKeyCrypto = await crypto.subtle.importKey(
      "raw",
      finishedKey,
      {
         name: "HMAC",
         hash: { name: `SHA-${sha}` },
      },
      true,
      ["sign", "verify"]
   );

   const hash = sha == 256 ? sha256.create() :
      sha == 384 ? sha384.create() : sha256.create();

   const transcriptHash = hash
      .update(unity(...messages))
      .digest();

   const verify_data = await crypto.subtle.sign(
      { name: "HMAC" },
      finishedKeyCrypto,
      transcriptHash
   )

   /* const _test_verify_data = await crypto.subtle.verify(
      { name: "HMAC" },
      finishedKeyCrypto,
      verify_data,
      transcriptHash
   ) */
   //verify_data.transcriptHash = transcriptHash;
   return new Finished(verify_data);
}