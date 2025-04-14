import { Byte } from "../src/dep.ts";
import { Finished, finished } from "../src/finished.js";
import { certificateMsg, clientHelloMsg, encryptedExtensionsMsg, serverHelloMsg } from "./certificateverify_test.js";
import { assertEquals } from "../src/dep.ts";

const finishedMsg = Byte.fromHex(
   `14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb
   dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07
   18`)

const finishedMsg_0 = Finished.from(finishedMsg.slice(4));

const hash = "SHA-256";
const sha = parseInt(hash.split("-")[1]);

const certificateVerifyMsg = Byte.fromHex(`0f 00 00 84 08 04 00 80 5a 74 7c
   5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
   b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
   86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
   be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
   5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
   3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3`)

const rsaPrivateKeyJwk = JSON.parse('{"kty":"RSA","alg":"PS256","key_ops":["sign"],"ext":true,"n":"tLtJj4J5MD2YCDY5mzbGmIwMaN5V4b24JtOQGiRh6v0t5JqR0BWrvJqVE3rObBrxnqpq-Yx87UMSCZjhh6gO4MywUksbAYw-C2MmTUSabTjiKl_aQwhGdIAwUw7wRhyMqdnvv66OptHQPivRk-_wq5qAAsR0KKbTWo2I159_Hj8","e":"AQAB","d":"BN6nBdQ6bqcgndgHIRGoPIHjIqWSeLM0gGQer3wKaYW44xxE9t5i4bTCMJ9hJud7fEHpIzFLv6OIEwXcEhfxbIGc5TjpIvNpgo0OVxldjISIRgIHsvqnJrz3CLvX239nn4k0kvwqYi4IlwqsRBzk4MMIjfJa5nkjPfijvaL_mUE","p":"5DX7fMg3N3VtrOqWq39ZoswQadt96xkOF-M6UysnPzCjJ6oKqrxYzWdGavmEX63Gdf4JSvksS9Hywbwz3S4FFQ","q":"yr07wOBDhmTI1MyfmZd6lNm7_q2OQ4cKuuP364tODu6K8dm0cZumGWzyy7ru6_izSQr-np_6dKiKpR_GRWKTAw","dp":"P1c0XCf-G2h-bnYWJ7eLG4JkM912D6C-pqas85SQqhtHzaSGnWj1hN1bUCm9Mgk7glhmH-cVAl5dcKRaCNPTGQ","dq":"GD2gE2O9LyiFysvcmWS_R2TxUXY2-GQBKG9xiTxSzP5ApsI9DQhrR8b7ENj9EEHgTe9-mkDOlXxBd5ThBBLROQ","qi":"g5ypoIXkKGsskORmmXosaB8hM5qjR3gU5N7BGDMFDtUN0TzAOASKQ8WbKsxBaInAN2Zf5a-mBZafjAHfpcqWnQ"}');

const rsaPrivateKey = await crypto.subtle.importKey('jwk', rsaPrivateKeyJwk, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign'])


const finished_key = Byte.fromHex(
   `00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85
   c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8`)

const finished_0 = await finished(finished_key, 256, clientHelloMsg, serverHelloMsg, encryptedExtensionsMsg, certificateMsg, certificateVerifyMsg);
