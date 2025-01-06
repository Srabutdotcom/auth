import { Uint16, Uint24, Struct, Constrained, Extension, x509, HandshakeType, ContentType } from "./dep.ts"

export class CertificateEntry extends Uint8Array {
   static from(array) {
      const copy = array.slice();
      let offset = 0
      const cert_data = Cert_data.from(copy.subarray(offset)); offset += cert_data.length;
      const extensions = Extensions.from(copy.subarray(offset));
      return new CertificateEntry(cert_data, extensions)
   }
   constructor(cert_data, extensions) {
      const struct = new Struct(cert_data, extensions);
      super(struct);
      this.cert_data = cert_data;
      this.extensions = extensions
      //const opaque = cert_data.opaque
      this.x509 = new x509.X509Certificate(btoa(String.fromCharCode(...cert_data.opaque)))
   }
}

class Cert_data extends Constrained {
   static from(array) {
      const copy = array.slice();
      const lengthOf = Uint24.from(copy).value;
      return new Cert_data(copy.subarray(3, lengthOf + 3))
   }
   constructor(opaque) {
      super(1, 2 ** 24 - 1, opaque);
      this.opaque = opaque
   }
}

class Extensions extends Constrained {
   static from(array) {
      const copy = array.slice();
      const _lengthOf = Uint16.from(copy).value;
      if (!_lengthOf) return new Extensions()
      let offset = 2;
      const extensions = [];
      while (true) {
         const extension = Extension.from(copy.subarray(offset)); offset += extension.length;
         extensions.push(extension);
         if (offset >= copy.length - 2) break;
      }
      return new Extensions(...extensions)
   }
   constructor(...extensions) {
      super(0, 2 ** 16 - 1, ...extensions);
      this.extensions = extensions
   }
}

export class Certificate extends Uint8Array {
   static from(array) {
      const copy = array.slice();
      let offset = 0;
      const certificate_request_context = Certificate_request_context.from(copy.subarray(offset));
      offset += certificate_request_context.length;
      const certificate_list = Certificate_list.from(copy.subarray(offset));
      return new Certificate(certificate_request_context, certificate_list)
   }
   constructor(certificate_request_context, certificate_list) {
      const struct = new Struct(certificate_request_context, certificate_list);
      super(struct);
      this.certificate_request_context = certificate_request_context.opaque;
      this.certificateEntries = certificate_list.certificateEntries
   }
   get handshake() { return HandshakeType.CERTIFICATE.handshake(this) }
   get record() { return ContentType.HANDSHAKE.tlsPlaintext(this.handshake) }
}

class Certificate_request_context extends Constrained {
   static from(array) {
      const copy = array.slice();
      const lengthOf = copy.at(0);
      return new Certificate_request_context(copy.subarray(1, lengthOf + 1))
   }
   constructor(opaque) {
      super(0, 2 ** 8 - 1, opaque);
      this.opaque = opaque
   }
}

class Certificate_list extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const _lengthOf = Uint24.from(copy).value;
      let offset = 3;
      const certificateEntries = []
      while (true) {
         const certificateEntry = CertificateEntry.from(copy.subarray(offset)); offset += certificateEntry.length;
         certificateEntries.push(certificateEntry)
         if (offset >= copy.length - 3) break;
      }
      return new Certificate_list(...certificateEntries)
   }
   constructor(...certificateEntries) {
      super(0, 2 ** 24 - 1, ...certificateEntries);
      this.certificateEntries = certificateEntries
   }
}
