import { Handshake } from "../src/dep.ts";

/**
 * Represents a `Finished` TLS handshake message, extending `Uint8Array`.
 */
export class Finished extends Uint8Array {
   /**
    * Creates a `Finished` instance from a handshake message.
    * @param {Handshake} handshake - The handshake message to create the `Finished` instance from.
    * @returns {Finished} The resulting `Finished` instance.
    */
   static fromHandshake(handshake: Handshake): Finished;
 
   /**
    * Creates a `Finished` instance from an array or array-like object.
    * @param {Uint8Array} array - The array or array-like object to create the `Finished` instance from.
    * @returns {Finished} The resulting `Finished` instance.
    */
   static from(array: Uint8Array): Finished;
 
   /**
    * Constructs a new `Finished` instance.
    * @param {Uint8Array} verify_data - The verification data for the `Finished` message.
    */
   constructor(verify_data: Uint8Array);
 
   /**
    * The verification data associated with this `Finished` instance.
    * @type {Uint8Array}
    */
   verify_data: Uint8Array;
 
   /**
    * Gets the handshake representation of the `Finished` message.
    * @returns {Uint8Array} The handshake message as a `Uint8Array`.
    */
   get handshake(): Uint8Array;
 
   /**
    * Gets the record representation of the `Finished` message.
    * @returns {Uint8Array} The record message as a `Uint8Array`.
    */
   get record(): Uint8Array;
 }