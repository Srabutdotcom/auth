/* import { Certificate } from "./certificate.js";
import { CertificateVerify } from "./certificateverify.js";
import { HandshakeType, Uint24 } from "./dep.ts";
import { Finished } from "./finished.js"; */

import { HandshakeType, safeuint8array } from "./dep.ts";

/* export function messageFromHandshake(handshake) {
   const copy = Uint8Array.from(handshake);
   const type = HandshakeType.fromValue(copy.at(0));
   const lengthOf = Uint24.from(copy.subarray(1)).value;
   const message = copy.subarray(4, lengthOf + 4)
   switch (type) {
      case HandshakeType.CERTIFICATE_VERIFY: return CertificateVerify.from(message).handshake
      case HandshakeType.CERTIFICATE: return Certificate.from(message).handshake
      case HandshakeType.FINISHED: return Finished.from(message).handshake
   }
} */

export class BooleanPlus extends Boolean {
   #data;
   static toFalse(value){ return new BooleanPlus(false, value)}
   static toTrue(value){ return new BooleanPlus(true, value)}
   /**
    * Creates an instance of BooleanWithInfo.
    * @param {boolean} value - The boolean value.
    * @param {any} [data=null] - Additional information associated with the boolean.
    */
   constructor(value, data = null) {
      super(value);
      this.#data = data;
   }

   /** @returns {any} The additional information */
   get data() {
      return this.#data;
   }

   /**
    * Sets additional information.
    * @param {any} data - The metadata to attach.
    */
   set data(data) {
      this.#data = data;
   }

   /**
    * Returns a string representation of the object.
    * @returns {string}
    */
   toString() {
      return `BooleanWithInfo(${this.valueOf()}, data: ${JSON.stringify(this.#data)})`;
   }

   /**
    * Converts to a plain object.
    * @returns {{value: boolean, data: any}}
    */
   toObject() {
      return { value: this.valueOf(), data: this.#data };
   }

   /**
    * Converts the instance to a JSON string.
    * @returns {string}
    */
   toJSON() {
      return JSON.stringify(this.toObject());
   }

   /**
    * Creates an instance from an object.
    * @param {{value: boolean, data: any}} obj
    * @returns {BooleanWithInfo}
    */
   static from(obj) {
      return new BooleanWithInfo(obj.value, obj.data);
   }
}

export class Transcript {
   #handshakes = []
   #clientHelloMsg = null;
   #serverHelloMsg = null;
   #encryptExtsMsg = null;
   #certificateMsg = null;
   #certificateVerifyMsg = null;

   constructor(...handshakes) {
      for (const handshake of handshakes) {
         this.insert(handshake)
      }
   }
   insertMany(...handshakes) {
      for (const handshake of handshakes) {
         this.insert(handshake)
      }
   }
   insert(handshake) {
      if (!this.#handshakes.length) {
         if (HandshakeType.fromValue(handshake[0]) !== HandshakeType.CLIENT_HELLO) throw Error(`Expected ClientHello`);
         this.#clientHelloMsg = handshake;
         this.#handshakes.push(handshake)
         return
      }
      if (handshake.isHRR) {
         const hashClientHello1 = handshake.message.cipher.hash.create().update(this.#handshakes[0]).digest();
         this.#handshakes[0] = safeuint8array(
            HandshakeType.MESSAGE_HASH.byte,
            Uint8Array.of(0, 0, hashClientHello1.length),
            hashClientHello1
         )
         this.#handshakes.push(handshake)
         return
      }
      switch (handshake?.type??HandshakeType.from(handshake)) {
         case HandshakeType.SERVER_HELLO:
            this.#serverHelloMsg = handshake;
            break;
         case HandshakeType.CLIENT_HELLO:
            this.#clientHelloMsg = handshake;
            break;
         case HandshakeType.ENCRYPTED_EXTENSIONS:
            this.#encryptExtsMsg = handshake;
            break;
         case HandshakeType.CERTIFICATE:
            this.#certificateMsg = handshake;
            break;
         case HandshakeType.CERTIFICATE_VERIFY:
            this.#certificateVerifyMsg = handshake;
            break;
         default:
            break;
      }
      this.#handshakes.push(handshake);
   }
   get byte() {
      return safeuint8array(...this.#handshakes)
   }
   get clientHelloMsg() {
      return this.#clientHelloMsg
   }
   get serverHelloMsg() {
      return this.#serverHelloMsg
   }
   get encryptedExtensionsMsg() {
      return this.#encryptExtsMsg
   }
   get certificateMsg(){
      return this.#certificateMsg
   }
   get certificateVerifyMsg(){
      return this.#certificateVerifyMsg
   }
}