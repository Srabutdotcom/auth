//@ts-self-types="../type/finished.d.ts"
import { ContentType, HandshakeType } from "./dep.ts";
import { messageFromHandshake } from "./utils.js";

export class Finished extends Uint8Array {
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
   get handshake(){ return HandshakeType.FINISHED.handshake(this)}
   get record() { return ContentType.HANDSHAKE.tlsPlaintext(this.handshake) }
}