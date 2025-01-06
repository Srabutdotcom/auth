import { Handshake, Constrained, SignatureScheme } from "../src/dep.ts";

/**
 * Represents a `CertificateVerify` TLS handshake message, extending `Uint8Array`.
 */
export class CertificateVerify extends Uint8Array {
   /**
    * Creates a `CertificateVerify` instance from a handshake message.
    * @param {Handshake} handshake - The handshake message to create the `CertificateVerify` instance from.
    * @returns {CertificateVerify} The resulting `CertificateVerify` instance.
    */
   static fromHandshake(handshake: Handshake): CertificateVerify;
 
   /**
    * Creates a `CertificateVerify` instance from an array or array-like object.
    * @param {Uint8Array} array - The array or array-like object to create the `CertificateVerify` instance from.
    * @returns {CertificateVerify} The resulting `CertificateVerify` instance.
    */
   static from(array: Uint8Array): CertificateVerify;
 
   /**
    * Constructs a new `CertificateVerify` instance.
    * @param {SignatureScheme} algorithm - The signature scheme algorithm.
    * @param {Signature} signature - The signature associated with the `CertificateVerify` message.
    */
   constructor(algorithm: SignatureScheme, signature: Signature);
 
   /**
    * The signature scheme algorithm.
    * @type {SignatureScheme}
    */
   algorithm: SignatureScheme;
 
   /**
    * The signature associated with this `CertificateVerify` instance.
    * @type {Signature}
    */
   signature: Signature;
 
   /**
    * Gets the handshake representation of the `CertificateVerify` message.
    * @returns {Uint8Array} The handshake message as a `Uint8Array`.
    */
   get handshake(): Uint8Array;
 
   /**
    * Gets the record representation of the `CertificateVerify` message.
    * @returns {Uint8Array} The record message as a `Uint8Array`.
    */
   get record(): Uint8Array;
 }
 
 /**
  * Represents a signature with a length constraint, extending `Constrained`.
  */
 export class Signature extends Constrained {
   /**
    * Creates a `Signature` instance from an array or array-like object.
    * @param {ArrayLike<number>} array - The array or array-like object to create the `Signature` instance from.
    * @returns {Signature} The resulting `Signature` instance.
    */
   static from(array: Uint8Array): Signature;
 
   /**
    * Constructs a new `Signature` instance.
    * @param {Uint8Array} opaque - The opaque data representing the signature.
    */
   constructor(opaque: Uint8Array);
 
   /**
    * The opaque data representing the signature.
    * @type {Uint8Array}
    */
   opaque: Uint8Array;
 }