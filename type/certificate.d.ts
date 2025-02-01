import { Constrained, Extension, Handshake, x509 } from "../src/dep.ts";
/**
 * Represents a TLS Certificate Entry, extending `Uint8Array`.
 */
export class CertificateEntry extends Uint8Array {
  /**
   * Creates a `CertificateEntry` instance from an array or array-like object.
   * @param {Uint8Array} array - The array or array-like object to create the `CertificateEntry` from.
   * @returns {CertificateEntry} The resulting `CertificateEntry` instance.
   */
  static from(array: Uint8Array): CertificateEntry;

  /**
   * Constructs a new `CertificateEntry` instance.
   * @param {Cert_data} cert_data - The certificate data.
   * @param {Extensions} extensions - The certificate extensions.
   */
  constructor(cert_data: Cert_data, extensions: Extensions);

  /**
   * The certificate data.
   * @type {Cert_data}
   */
  cert_data: Cert_data;

  /**
   * The certificate extensions.
   * @type {Extensions}
   */
  extensions: Extensions;

  /**
   * The parsed X.509 certificate.
   * @type {x509.X509Certificate}
   */
  x509: x509.X509Certificate;
}

/**
 * Represents certificate data with length constraints, extending `Constrained`.
 */
declare class Cert_data extends Constrained {
  /**
   * Creates a `Cert_data` instance from an array or array-like object.
   * @param {Uint8Array} array - The array to create the `Cert_data` from.
   * @returns {Cert_data} The resulting `Cert_data` instance.
   */
  static from(array: Uint8Array): Cert_data;

  /**
   * Constructs a new `Cert_data` instance.
   * @param {Uint8Array} opaque - The opaque certificate data.
   */
  constructor(opaque: Uint8Array);

  /**
   * The opaque certificate data.
   * @type {Uint8Array}
   */
  opaque: Uint8Array;
}

/**
 * Represents certificate extensions, extending `Constrained`.
 */
declare class Extensions extends Constrained {
  /**
   * Creates an `Extensions` instance from an array or array-like object.
   * @param {Uint8Array} array - The array to create the `Extensions` from.
   * @returns {Extensions} The resulting `Extensions` instance.
   */
  static from(array: Uint8Array): Extensions;

  /**
   * Constructs a new `Extensions` instance.
   * @param {...Extension[]} extensions - The list of extensions.
   */
  constructor(...extensions: Extension[]);

  /**
   * The list of extensions.
   * @type {Extension[]}
   */
  extensions: Extension[];
}

/**
 * Represents a TLS Certificate message, extending `Uint8Array`.
 */
export class Certificate extends Uint8Array {
  /**
   * Creates a `Certificate` instance from a handshake message.
   * @param {Handshake} handshake - The handshake message.
   * @returns {Certificate} The resulting `Certificate` instance.
   */
  static fromHandshake(handshake: Handshake): Certificate;

  /**
   * Creates a `Certificate` instance from an array or array-like object.
   * @param {Uint8Array} array - The array to create the `Certificate` from.
   * @returns {Certificate} The resulting `Certificate` instance.
   */
  static from(array: Uint8Array): Certificate;

  /**
   * Constructs a new `Certificate` instance.
   * @param {Certificate_request_context} certificate_request_context - The certificate request context.
   * @param {Certificate_list} certificate_list - The list of certificates.
   */
  constructor(
    certificate_request_context: Certificate_request_context,
    certificate_list: Certificate_list,
  );

  /**
   * The certificate request context.
   * @type {Uint8Array}
   */
  certificate_request_context: Uint8Array;

  /**
   * The list of certificate entries.
   * @type {CertificateEntry[]}
   */
  certificateEntries: CertificateEntry[];

  /**
   * Gets the handshake representation of the `Certificate` message.
   * @returns {Uint8Array} The handshake message.
   */
  get handshake(): Uint8Array;

  /**
   * Gets the record representation of the `Certificate` message.
   * @returns {Uint8Array} The record message.
   */
  get record(): Uint8Array;
  /**
   * Verifies the certificate entries in the current instance.
   *
   * @returns {Promise<boolean>} Resolves to `true` if verification is successful, otherwise `false`.
   */
  verify(): Promise<boolean>;
}

/**
 * Represents the certificate request context, extending `Constrained`.
 */
declare class Certificate_request_context extends Constrained {
  /**
   * Creates a `Certificate_request_context` from an array or array-like object.
   * @param {Uint8Array} array - The array to create the context from.
   * @returns {Certificate_request_context} The resulting context.
   */
  static from(array: Uint8Array): Certificate_request_context;

  /**
   * Constructs a new `Certificate_request_context` instance.
   * @param {Uint8Array} opaque - The opaque context data.
   */
  constructor(opaque: Uint8Array);

  /**
   * The opaque context data.
   * @type {Uint8Array}
   */
  opaque: Uint8Array;
}

/**
 * Represents a list of certificates, extending `Constrained`.
 */
declare class Certificate_list extends Constrained {
  /**
   * Creates a `Certificate_list` from an array or array-like object.
   * @param {Uint8Array} array - The array to create the list from.
   * @returns {Certificate_list} The resulting list.
   */
  static from(array: Uint8Array): Certificate_list;

  /**
   * Constructs a new `Certificate_list` instance.
   * @param {...CertificateEntry[]} certificateEntries - The list of certificate entries.
   */
  constructor(...certificateEntries: CertificateEntry[]);

  /**
   * The list of certificate entries.
   * @type {CertificateEntry[]}
   */
  certificateEntries: CertificateEntry[];
}

/**
 * Verifies the signature of an X.509 certificate using the issuer's public key.
 *
 * @param {x509.X509Certificate} first - The X.509 certificate whose signature is being verified.
 * @param {x509.X509Certificate} last - The issuing X.509 certificate that contains the public key.
 *
 * @returns {Promise<boolean>} Resolves to `true` if the signature is valid, otherwise `false`.
 */
export function verify(
  first: x509.X509Certificate,
  last: x509.X509Certificate,
): Promise<boolean>;

/**
 * Verifies a chain of X.509 certificate entries.
 *
 * @param {Array<{ x509: X509Certificate }>} certificateEntries - An array of certificate entries, where each entry contains an `x509` certificate.
 * @returns {Promise<boolean>} Resolves to `true` if the certificate chain is valid, otherwise `false`.
 */
export function verifyCertificateEntries(certificateEntries: { x509: x509.X509Certificate }[]): Promise<boolean>;
