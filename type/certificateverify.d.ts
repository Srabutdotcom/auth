import { SignatureScheme } from "../src/dep.ts";

/**
 * {@link CertificateVerify} https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
 * @class
 * @extends Uint8Array
 */
export class CertificateVerify extends Uint8Array {
  #algorithm: SignatureScheme | null;
  #signature: Uint8Array | null;

  /**
   * Sanitizes the input Uint8Array for creating a CertificateVerify instance.
   * @static
   * @param {Uint8Array} array - The Uint8Array to sanitize.
   * @returns {Uint8Array[]} - A BooleanPlus object indicating success or failure, with the sanitized data if successful.
   */
  static sanitize(array: Uint8Array): Uint8Array[];

  /**
   * Creates a new CertificateVerify instance from a Uint8Array.
   * @static
   * @param {Uint8Array} array - The Uint8Array to create the CertificateVerify from.
   * @returns {CertificateVerify} A new CertificateVerify instance.
   */
  static from(array: Uint8Array): CertificateVerify;

  /**
   * Constructs a new CertificateVerify instance.
   * @param {...(number | Uint8Array)} args - The arguments to create the CertificateVerify.
   * - If a single Uint8Array is provided, it will be sanitized and used to create the new instance.
   * - Otherwise, the arguments are treated as byte values.
   */
  constructor(...args: (number | Uint8Array)[]);

  /**
   * The signature algorithm.
   * @readonly
   * @type {SignatureScheme}
   */
  get algorithm(): SignatureScheme;

  /**
   * The signature value.
   * @readonly
   * @type {Uint8Array}
   */
  get signature(): Uint8Array;
}

/**
 * Generates a cryptographic signature based on the TLS handshake messages.
 *
 * @param clientHelloMsg - The ClientHello message in Uint8Array format.
 * @param serverHelloMsg - The ServerHello message in Uint8Array format.
 * @param encryptedExtensionsMsg - The EncryptedExtensions message in Uint8Array format.
 * @param certificateMsg - The Certificate message in Uint8Array format.
 * @param privateKey - The private key used for signing (CryptoKey).
 * @param algo - The algorithm identifier for signing.
 * @returns A promise that resolves to a Uint8Array containing the generated signature.
 */
export function createSignature(
  clientHelloMsg: Uint8Array,
  serverHelloMsg: Uint8Array,
  encryptedExtensionsMsg: Uint8Array,
  certificateMsg: Uint8Array,
  privateKey: CryptoKey,
  algo: AlgorithmIdentifier,
): Promise<Uint8Array>;

/**
 * Verifies the signature in the CertificateVerify message using the provided handshake messages.
 *
 * @param clientHelloMsg - The ClientHello message in Uint8Array format.
 * @param serverHelloMsg - The ServerHello message in Uint8Array format.
 * @param encryptedExtensionsMsg - The EncryptedExtensions message in Uint8Array format.
 * @param certificateMsg - The Certificate message in Uint8Array format.
 * @param certificateVerifyMsg - The CertificateVerify message in Uint8Array format.
 * @returns A promise that resolves to a boolean indicating whether the signature is valid.
 */
export function verifyCertificateVerify(
  transcriptMsg: Uint8Array
): Promise<boolean>;
