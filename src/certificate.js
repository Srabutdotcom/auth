//@ts-self-types="../type/certificate.d.ts"
import { Uint16, Uint24, Extension, x509, parseItems } from "./dep.ts"
//import { messageFromHandshake } from "./utils.js";

export class CertificateEntry extends Uint8Array {
   #data
   #extensions
   #x509
   static sanitize(array) {
      const len_1 = Uint24.from(array).value;
      if (len_1 > 2 ** 24 - 1) throw Error(`Max. certificate data length is 2^24-1`);
      const len_2 = Uint16.from(array.subarray(len_1 + 3)).value;
      if (len_2 > 2 ** 16 - 1) throw Error(`Max. extensions length is 2^16-1`);
      return [array.slice(0, len_1 + len_2 + 5)]
   }
   static from(array) { return new CertificateEntry(array) }
   constructor(...args) {
      args = (args[0] instanceof Uint8Array) ? CertificateEntry.sanitize(args[0]) : args;
      super(...args)
   }
   get data() {
      if (this.#data) return this.#data
      const lengthOf = Uint24.from(this).value;
      this.#data = this.subarray(3, 3 + lengthOf);
      return this.#data;
   }
   get x509() {
      if (this.#x509) return this.#x509;
      this.#x509 = new x509.X509Certificate(this.data)//(btoa(String.fromCharCode(...this.data)));
      return this.#x509
   }
   get extensions() {
      if (this.#extensions) return this.#extensions;
      const lengthOf = Uint16.from(this.subarray(this.data.length + 3)).value;
      this.#extensions = parseItems(this, this.data.length + 3, lengthOf, Extension);
      return this.#extensions
   }
}
/* export class CertificateEntry_0 extends Uint8Array {
   static from(array) {
      const copy = Uint8Array.from(array);
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
      const copy = Uint8Array.from(array);
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
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      if (!lengthOf) return new Extensions()
      const extensions = parseItems(copy, 2, lengthOf, Extension);
      return new Extensions(...extensions)
   }
   constructor(...extensions) {
      super(0, 2 ** 16 - 1, ...extensions);
      this.extensions = extensions
   }
} */

export class Certificate extends Uint8Array {
   #context
   #list
   static sanitize(array) {
      const lengthOf_1 = array.at(0);
      if (lengthOf_1 > 255) throw Error(`Context must less than 256 byte`)
      const lengthOf_2 = Uint24.from(array.subarray(1 + lengthOf_1)).value;
      if (lengthOf_1 > 16777215) throw Error(`Context must less than 16777215 byte`);
      const output = array.slice(0, lengthOf_1 + lengthOf_2 + 4)
      return [output]
   }
   static from(array) { return new Certificate(array) }
   constructor(...args) {
      args = (args[0] instanceof Uint8Array) ? Certificate.sanitize(args[0]) : args
      super(...args)
   }
   get context() {
      if (this.#context) return this.#context;
      const lengthOf = this.at(0);
      this.#context ||= this.subarray(1, 1 + lengthOf);
      return this.#context;
   }
   get list() {
      if (this.#list) return this.#list;
      const lengthOf = Uint24.from(this.subarray(1 + this.context.length)).value;
      this.#list ||= parseItems(this, this.#context.length + 4, lengthOf, CertificateEntry);
      return this.#list;
   }
   async verify() {
      return await verifyCertificateEntries([...this.list])
   }
   async publicKey(algo) {
      const cert = [...this.list].at(0).x509;
      return await crypto.subtle.importKey(
         "spki",
         cert.publicKey.rawData,
         algo,//cert.signatureAlgorithm,//cert.publicKey.algorithm, 
         true,
         ["verify"])
   }
}

/* export class Certificate_0 extends Uint8Array {
   static fromHandshake(handshake) {
      return messageFromHandshake(handshake)
   }
   static from(array) {
      const copy = Uint8Array.from(array);
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
   get handshake() { return new Handshake(HandshakeType.CERTIFICATE, this) }
   get record() { return this.handshake.record }

   async verify() {
      return await verifyCertificateEntries(this.list)
   }
}

class Certificate_request_context extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
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
      const lengthOf = Uint24.from(copy).value;
      const certificateEntries = parseItems(copy, 3, lengthOf, CertificateEntry)
      return new Certificate_list(...certificateEntries)
   }
   constructor(...certificateEntries) {
      super(0, 2 ** 24 - 1, ...certificateEntries);
      this.certificateEntries = certificateEntries
   }
} */

export async function verify(first, last) {
   return await first.verify(last);
   /* const alternative = await first.verify({publicKey: last.publicKey})
   const publicKey = await crypto.subtle.importKey("spki", last.publicKey.rawData, last.signatureAlgorithm, true, ["verify"])
   const signature = first.signature
   const data = first.tbs
   const algoritma = first.signatureAlgorithm;
   const result = await crypto.subtle.verify(
      algoritma, publicKey, signature, data
   )
   return result; */
}

async function verifyCertificateEntries(certificateEntries) {
   if (certificateEntries.length == 1) {
      const first = certificateEntries[0].x509;
      if (!isSelfSigned(first)) return false;
      if (isExpired(first)) return false
      const valid = await verify(first, first)
      if (!valid) return false
      return true
   } else if (certificateEntries.length > 1) {
      for (let i = 0; i < certificateEntries.length - 1; i++) {
         const first = certificateEntries[i].x509;
         if (isExpired(first)) return false;
         const next = certificateEntries[i + 1].x509;
         if (isExpired(next)) return false;
         if (first.issuer !== next.subject) return false
         const valid = await verify(first, next);
         if (!valid) return false
      }
      return true
   }
   return false
}

function isSelfSigned(x509Certificate) {
   return x509Certificate.issuer == x509Certificate.subject
}

function isExpired(x509Certificate) {
   const { notAfter, notBefore } = x509Certificate
   const today = new Date;
   return notBefore > today && today > notAfter
}

