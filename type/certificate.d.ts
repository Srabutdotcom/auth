import { X509Certificate } from "@peculiar/x509";
import { Extension } from "../src/dep.ts"

/**
 * Represents a Certificate Entry in TLS 1.3.
 * This class extends `Uint8Array` and provides access to certificate data, X.509 parsing, and extensions.
 */
export class CertificateEntry extends Uint8Array {
  /** The certificate data */
  #data: Uint8Array;
  
  /** The parsed X.509 certificate */
  #x509: X509Certificate;

  /** The certificate extensions */
  #extensions: Set<Extension>;

  /**
   * Sanitizes the input Uint8Array to ensure it follows the CertificateEntry structure.
   * @param array - The input Uint8Array.
   * @returns A new Uint8Array slice containing the sanitized data.
   * @throws {Error} If the certificate data or extensions exceed their maximum allowed size.
   */
  static sanitize(array: Uint8Array): [Uint8Array];

  /**
   * Creates a `CertificateEntry` instance from a Uint8Array.
   * @param array - The input Uint8Array.
   * @returns A new `CertificateEntry` instance.
   */
  static from(array: Uint8Array): CertificateEntry;

  /**
   * Constructs a `CertificateEntry` instance.
   * @param args - The arguments passed to the constructor.
   */
  constructor(...args: any[]);

  /**
   * Gets the certificate data as a Uint8Array.
   */
  get data(): Uint8Array;

  /**
   * Gets the parsed X.509 certificate from the certificate data.
   */
  get x509(): X509Certificate;

  /**
   * Gets the certificate extensions as a Set of `Extension` objects.
   */
  get extensions(): Set<Extension>
}

/**
 * Represents a TLS 1.3 Certificate message.
 * This class extends `Uint8Array` and provides access to the certificate request context and certificate list.
 */
export class Certificate extends Uint8Array {
  /** The certificate request context */
  #context: Uint8Array;

  /** The list of certificate entries */
  #list: Set<CertificateEntry>;

  /**
   * Sanitizes the input Uint8Array to ensure it follows the Certificate message structure.
   * @param array - The input Uint8Array.
   * @returns A new Uint8Array slice containing the sanitized data.
   * @throws {Error} If the context or certificate list exceeds the maximum allowed size.
   */
  static sanitize(array: Uint8Array): [Uint8Array];

  /**
   * Creates a `Certificate` instance from a Uint8Array.
   * @param array - The input Uint8Array.
   * @returns A new `Certificate` instance.
   */
  static from(array: Uint8Array): Certificate;

  /**
   * Constructs a `Certificate` instance.
   * @param args - The arguments passed to the constructor.
   */
  constructor(...args: any[]);

  /**
   * Gets the certificate request context as a Uint8Array.
   */
  get context(): Uint8Array;

  /**
   * Gets the list of certificate entries as a Set of `CertificateEntry` objects.
   */
  get list(): Set<CertificateEntry>;

  /**
   * Verifies the certificate chain asynchronously.
   * @returns A promise that resolves to the verification result.
   */
  verify(): Promise<boolean>;
}

/**
 * Verifies a digital signature using the Web Crypto API.
 * 
 * @param first - The certificate or object containing the signature and data to verify.
 * @param first.signature - The signature to be verified.
 * @param first.tbs - The data that was signed (to be verified against the signature).
 * @param last - The certificate or object containing the public key and signature algorithm.
 * @param last.publicKey.rawData - The raw SPKI-encoded public key used for verification.
 * @param last.signatureAlgorithm - The signature algorithm used for verification.
 * @returns A promise that resolves to `true` if the signature is valid, otherwise `false`.
 */
export function verify(
  first: { signature: ArrayBuffer; tbs: ArrayBuffer },
  last: { publicKey: { rawData: ArrayBuffer }; signatureAlgorithm: AlgorithmIdentifier }
): Promise<boolean>;
