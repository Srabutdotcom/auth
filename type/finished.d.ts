
/**
 * Represents the Finished message in the TLS 1.3 handshake.
 */
export class Finished extends Uint8Array {
  /**
   * Creates a new instance of Finished from the provided arguments.
   * @param args - The arguments used to construct the Finished message.
   * @returns A new instance of Finished.
   */
  static from(...args: ConstructorParameters<typeof Uint8Array>): Finished;

  /**
   * Constructs a Finished message.
   * @param args - The arguments used to initialize the Finished message.
   */
  constructor(...args: ConstructorParameters<typeof Uint8Array>);
}

/**
 * Computes the Finished message for the TLS 1.3 handshake.
 * @param finishedKey - The key used to generate the HMAC signature.
 * @param sha - The hash algorithm to use (256 or 384).
 * @param messages - The handshake messages from ClientHello to CertificateVerify used for the transcript hash.
 * @returns A `Finished` instance containing the verify data.
 */
export function finished(
  finishedKey: Uint8Array,
  sha?: 256 | 384,
  ...messages: Uint8Array[]
): Promise<Finished>;