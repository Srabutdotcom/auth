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