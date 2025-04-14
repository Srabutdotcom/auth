import { Byte } from "../src/dep.ts";
import { Certificate } from "../src/certificate.js";
import { assertEquals } from "../src/dep.ts";

/* Deno.test("Certificate", () => {
   const certificateMsg = Handshake.from(HexaDecimal.fromString(`0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
      01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
      86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
      72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
      0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
      03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
      0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
      82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
      d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
      1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
      4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
      80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
      ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
      01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
      03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
      01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
      72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
      e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
      51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
      c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
      1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
      96 12 29 ac 91 87 b4 2b 4d e1 00 00`).byte)

   const certificateMsg_back = Certificate.from(certificateMsg.message).handshake;
   const certificateMsg_back_0 = Certificate.fromHandshake(certificateMsg);
   assertEquals(certificateMsg.toString(), certificateMsg_back.toString())
   assertEquals(certificateMsg.toString(), certificateMsg_back_0.toString())
}) */

const cert = Byte.fromHex(`00 00 01 b5 00 01 b0 30 82
   01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
   86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
   72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
   0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
   03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
   0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
   82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
   d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
   1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
   4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
   80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
   ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
   01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
   03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
   01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
   72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
   e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
   51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
   c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
   1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
   96 12 29 ac 91 87 b4 2b 4d e1 00 00`);

/**
 * If the Issuer and Subject are the same, the certificate is self-signed (root CA). Otherwise, it's an intermediate or leaf certificate.
 */

const back = Certificate.from(cert);
const list = [...back.list];
const x509 = list[0].x509;
const verify = await back.verify();

const certChain = Uint8Array.of(/* 11,0,15,172, */0,0,15,168,0,5,36,48,130,5,32,48,130,4,8,160,3,2,1,2,2,16,41,76,14,175,26,205,80,212,10,68,10,120,202,163,132,78,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,48,59,49,11,48,9,6,3,85,4,6,19,2,85,83,49,30,48,28,6,3,85,4,10,19,21,71,111,111,103,108,101,32,84,114,117,115,116,32,83,101,114,118,105,99,101,115,49,12,48,10,6,3,85,4,3,19,3,87,82,50,48,30,23,13,50,53,48,49,50,48,48,56,51,55,48,53,90,23,13,50,53,48,52,49,52,48,56,51,55,48,52,90,48,25,49,23,48,21,6,3,85,4,3,19,14,115,109,116,112,46,103,109,97,105,108,46,99,111,109,48,130,1,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,130,1,15,0,48,130,1,10,2,130,1,1,0,209,58,249,93,6,230,107,203,177,78,198,90,56,155,36,149,101,188,209,92,175,229,101,147,94,241,121,166,155,64,199,49,118,49,1,172,19,148,96,236,77,35,129,72,223,3,101,190,205,96,44,192,165,141,193,41,69,237,209,165,68,207,16,216,68,248,130,119,153,171,215,106,28,27,112,131,244,67,142,215,61,5,76,78,90,210,162,208,54,242,223,241,90,229,92,51,79,207,109,97,156,97,78,202,63,204,172,172,160,48,225,32,51,196,160,77,242,90,224,174,214,220,18,169,123,60,239,21,153,28,246,55,212,171,221,173,143,205,108,11,184,118,15,12,0,200,203,5,123,116,207,124,208,71,190,184,214,85,61,167,251,147,187,24,128,233,41,147,92,165,251,202,248,66,161,58,79,221,108,5,45,48,239,12,217,177,152,118,81,202,154,200,238,39,197,30,237,174,42,46,142,174,254,124,82,154,172,253,158,61,219,201,124,191,124,123,79,106,194,26,240,246,118,222,58,60,80,173,66,29,140,43,207,196,194,73,173,169,139,206,33,210,151,205,115,121,88,144,67,186,39,216,224,145,117,179,2,3,1,0,1,163,130,2,64,48,130,2,60,48,14,6,3,85,29,15,1,1,255,4,4,3,2,5,160,48,19,6,3,85,29,37,4,12,48,10,6,8,43,6,1,5,5,7,3,1,48,12,6,3,85,29,19,1,1,255,4,2,48,0,48,29,6,3,85,29,14,4,22,4,20,121,66,173,26,6,237,29,203,52,226,184,113,90,6,239,71,79,55,143,191,48,31,6,3,85,29,35,4,24,48,22,128,20,222,27,30,237,121,21,212,62,55,36,195,33,187,236,52,57,109,66,178,48,48,88,6,8,43,6,1,5,5,7,1,1,4,76,48,74,48,33,6,8,43,6,1,5,5,7,48,1,134,21,104,116,116,112,58,47,47,111,46,112,107,105,46,103,111,111,103,47,119,114,50,48,37,6,8,43,6,1,5,5,7,48,2,134,25,104,116,116,112,58,47,47,105,46,112,107,105,46,103,111,111,103,47,119,114,50,46,99,114,116,48,25,6,3,85,29,17,4,18,48,16,130,14,115,109,116,112,46,103,109,97,105,108,46,99,111,109,48,19,6,3,85,29,32,4,12,48,10,48,8,6,6,103,129,12,1,2,1,48,54,6,3,85,29,31,4,47,48,45,48,43,160,41,160,39,134,37,104,116,116,112,58,47,47,99,46,112,107,105,46,103,111,111,103,47,119,114,50,47,55,53,114,52,90,121,65,51,118,65,48,46,99,114,108,48,130,1,3,6,10,43,6,1,4,1,214,121,2,4,2,4,129,244,4,129,241,0,239,0,117,0,207,17,86,238,213,46,124,175,243,135,91,217,105,46,155,233,26,113,103,74,176,23,236,172,1,210,91,119,206,204,59,8,0,0,1,148,131,18,173,186,0,0,4,3,0,70,48,68,2,32,34,60,48,193,6,234,79,2,225,241,112,122,113,130,45,164,10,179,161,47,57,103,131,230,232,59,51,233,162,169,38,188,2,32,125,21,82,196,127,8,105,12,119,28,126,123,133,72,59,203,33,193,77,163,211,119,165,85,185,53,247,12,53,239,235,159,0,118,0,125,89,30,18,225,120,42,123,28,97,103,124,94,253,248,208,135,92,20,160,78,149,158,185,3,47,217,14,140,46,121,184,0,0,1,148,131,18,173,180,0,0,4,3,0,71,48,69,2,33,0,205,10,97,185,148,164,38,142,226,213,217,28,173,252,24,138,209,66,65,117,114,1,15,17,131,73,196,44,136,82,6,107,2,32,105,160,163,215,218,62,140,76,161,121,89,44,242,232,93,16,3,133,83,209,13,173,225,168,62,159,151,150,166,214,253,78,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,130,1,1,0,144,228,116,246,15,24,181,70,100,55,36,117,188,33,160,14,103,110,243,127,99,134,144,173,243,116,242,144,141,70,18,78,149,62,8,177,175,165,127,98,139,173,202,62,41,83,203,203,54,192,69,114,191,85,47,37,26,88,246,255,102,164,90,20,35,11,33,49,129,129,100,7,194,241,161,170,171,70,115,72,66,83,167,159,188,172,146,38,20,109,83,106,111,228,114,72,168,98,49,80,190,171,34,92,131,124,216,80,172,181,60,204,211,214,139,26,237,169,170,206,190,84,182,59,22,36,70,239,16,105,3,235,182,102,215,147,129,1,108,178,57,185,234,235,89,252,118,175,38,48,106,49,12,56,116,44,177,172,141,182,193,177,155,124,61,52,6,136,122,93,129,122,157,133,59,64,162,54,29,59,47,59,246,56,53,61,183,74,141,78,112,56,7,73,166,212,25,170,191,98,169,244,68,116,202,96,205,42,191,194,117,114,16,67,140,3,0,166,132,23,122,229,254,86,245,119,137,139,252,87,211,119,92,115,101,171,207,215,219,162,110,22,144,6,113,176,37,229,251,95,44,15,55,77,2,187,0,0,0,5,15,48,130,5,11,48,130,2,243,160,3,2,1,2,2,16,127,240,5,160,124,76,222,209,0,173,157,102,165,16,123,152,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,48,71,49,11,48,9,6,3,85,4,6,19,2,85,83,49,34,48,32,6,3,85,4,10,19,25,71,111,111,103,108,101,32,84,114,117,115,116,32,83,101,114,118,105,99,101,115,32,76,76,67,49,20,48,18,6,3,85,4,3,19,11,71,84,83,32,82,111,111,116,32,82,49,48,30,23,13,50,51,49,50,49,51,48,57,48,48,48,48,90,23,13,50,57,48,50,50,48,49,52,48,48,48,48,90,48,59,49,11,48,9,6,3,85,4,6,19,2,85,83,49,30,48,28,6,3,85,4,10,19,21,71,111,111,103,108,101,32,84,114,117,115,116,32,83,101,114,118,105,99,101,115,49,12,48,10,6,3,85,4,3,19,3,87,82,50,48,130,1,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,130,1,15,0,48,130,1,10,2,130,1,1,0,169,255,156,127,69,30,112,168,83,159,202,217,229,13,222,70,87,87,125,188,143,154,90,172,70,241,132,154,187,145,219,201,251,47,1,251,146,9,0,22,94,160,28,248,193,171,249,120,47,74,204,216,133,162,216,89,60,14,211,24,251,177,245,36,13,38,238,182,91,100,118,124,20,199,47,122,206,168,76,183,244,217,8,252,223,135,35,53,32,168,226,105,226,140,78,63,177,89,250,96,162,30,179,201,32,83,25,130,202,54,83,109,96,77,233,0,145,252,118,141,92,8,15,10,194,220,241,115,107,197,19,110,10,79,122,194,242,2,28,46,180,99,131,218,49,246,45,117,48,178,251,171,194,110,219,169,192,14,185,249,103,212,195,37,87,116,235,5,180,233,142,181,222,40,205,204,122,20,228,113,3,203,77,97,46,97,87,197,25,169,11,152,132,26,232,121,41,217,178,141,47,255,87,106,102,224,206,171,149,168,41,150,99,112,18,103,30,58,225,219,176,33,113,215,124,158,253,170,23,110,254,43,251,56,23,20,209,102,167,175,154,181,112,204,200,99,129,58,140,192,42,169,118,55,206,227,2,3,1,0,1,163,129,254,48,129,251,48,14,6,3,85,29,15,1,1,255,4,4,3,2,1,134,48,29,6,3,85,29,37,4,22,48,20,6,8,43,6,1,5,5,7,3,1,6,8,43,6,1,5,5,7,3,2,48,18,6,3,85,29,19,1,1,255,4,8,48,6,1,1,255,2,1,0,48,29,6,3,85,29,14,4,22,4,20,222,27,30,237,121,21,212,62,55,36,195,33,187,236,52,57,109,66,178,48,48,31,6,3,85,29,35,4,24,48,22,128,20,228,175,43,38,113,26,43,72,39,133,47,82,102,44,239,240,137,19,113,62,48,52,6,8,43,6,1,5,5,7,1,1,4,40,48,38,48,36,6,8,43,6,1,5,5,7,48,2,134,24,104,116,116,112,58,47,47,105,46,112,107,105,46,103,111,111,103,47,114,49,46,99,114,116,48,43,6,3,85,29,31,4,36,48,34,48,32,160,30,160,28,134,26,104,116,116,112,58,47,47,99,46,112,107,105,46,103,111,111,103,47,114,47,114,49,46,99,114,108,48,19,6,3,85,29,32,4,12,48,10,48,8,6,6,103,129,12,1,2,1,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,130,2,1,0,69,117,139,229,31,59,68,19,150,26,171,88,241,53,201,111,61,210,208,51,74,134,51,186,87,81,79,238,196,52,218,22,18,76,191,19,159,13,212,84,233,72,121,192,48,60,148,37,242,26,244,186,50,148,182,51,114,11,133,238,9,17,37,52,148,225,111,66,219,130,155,123,127,42,154,169,255,127,169,210,222,74,32,203,179,251,3,3,184,248,7,5,218,89,146,47,24,70,152,206,175,114,190,36,38,177,30,0,77,189,8,173,147,65,68,10,187,199,213,1,133,191,147,87,227,223,116,18,83,14,17,37,211,155,220,222,203,39,110,179,194,185,51,98,57,194,224,53,225,91,167,9,46,25,203,145,42,118,92,241,223,202,35,132,64,165,111,255,154,65,224,181,239,50,209,133,174,175,37,9,240,98,197,110,194,200,110,50,253,184,218,226,206,74,145,74,243,133,85,78,177,117,214,72,51,47,111,132,217,18,92,159,212,113,152,99,37,141,105,92,10,107,125,242,65,189,232,187,143,228,34,215,157,101,69,232,76,10,135,218,233,96,102,136,14,31,199,225,78,86,197,118,255,180,122,87,105,242,2,34,9,38,65,29,218,116,162,229,41,243,196,154,229,93,214,170,122,253,225,183,43,102,56,251,232,41,102,186,239,160,19,47,248,115,126,240,218,64,17,28,93,221,143,166,252,190,219,190,86,248,50,156,31,65,65,109,126,182,197,235,198,139,54,183,23,140,157,207,25,122,52,159,33,147,196,126,116,53,210,170,253,76,109,20,245,201,176,121,91,73,60,243,191,23,72,232,239,154,38,19,12,135,242,115,214,156,197,82,107,99,247,50,144,120,169,107,235,94,214,147,161,191,188,24,61,139,89,246,138,198,5,94,82,24,226,102,224,218,193,220,173,90,37,170,244,69,252,241,11,120,164,175,176,242,115,164,48,168,52,193,83,127,66,150,229,72,65,235,144,70,12,6,220,203,146,198,94,243,68,68,67,70,41,70,160,166,252,185,142,57,39,57,177,90,226,177,173,252,19,255,142,252,38,225,212,254,132,241,80,90,142,151,107,45,42,121,251,64,100,234,243,61,189,91,225,160,4,176,151,72,28,66,245,234,90,28,205,38,200,81,255,20,153,103,137,114,95,29,236,173,90,221,0,0,0,5,102,48,130,5,98,48,130,4,74,160,3,2,1,2,2,16,119,189,13,108,219,54,249,26,234,33,15,196,240,88,211,13,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,48,87,49,11,48,9,6,3,85,4,6,19,2,66,69,49,25,48,23,6,3,85,4,10,19,16,71,108,111,98,97,108,83,105,103,110,32,110,118,45,115,97,49,16,48,14,6,3,85,4,11,19,7,82,111,111,116,32,67,65,49,27,48,25,6,3,85,4,3,19,18,71,108,111,98,97,108,83,105,103,110,32,82,111,111,116,32,67,65,48,30,23,13,50,48,48,54,49,57,48,48,48,48,52,50,90,23,13,50,56,48,49,50,56,48,48,48,48,52,50,90,48,71,49,11,48,9,6,3,85,4,6,19,2,85,83,49,34,48,32,6,3,85,4,10,19,25,71,111,111,103,108,101,32,84,114,117,115,116,32,83,101,114,118,105,99,101,115,32,76,76,67,49,20,48,18,6,3,85,4,3,19,11,71,84,83,32,82,111,111,116,32,82,49,48,130,2,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,130,2,15,0,48,130,2,10,2,130,2,1,0,182,17,2,139,30,227,161,119,155,59,220,191,148,62,183,149,167,64,60,161,253,130,249,125,50,6,130,113,246,246,140,127,251,232,219,188,106,46,151,151,163,140,75,249,43,246,177,249,206,132,29,177,249,197,151,222,239,185,242,163,233,188,18,137,94,167,170,82,171,248,35,39,203,164,177,156,99,219,215,153,126,240,10,94,235,104,166,244,198,90,71,13,77,16,51,227,78,177,19,163,200,24,108,75,236,252,9,144,223,157,100,41,37,35,7,161,180,210,61,46,96,224,207,210,9,135,187,205,72,240,77,194,194,122,136,138,187,186,207,89,25,214,175,143,176,7,176,158,49,241,130,193,192,223,46,166,109,108,25,14,181,216,126,38,26,69,3,61,176,121,164,148,40,173,15,127,38,229,168,8,254,150,232,60,104,148,83,238,131,58,136,43,21,150,9,178,224,122,140,46,117,214,156,235,167,86,100,143,150,79,104,174,61,151,194,132,143,192,188,64,192,11,92,189,246,135,179,53,108,172,24,80,127,132,224,76,205,146,211,32,233,51,188,82,153,175,50,181,41,179,37,42,180,72,249,114,225,202,100,247,230,130,16,141,232,157,194,138,136,250,56,102,138,252,99,249,1,249,120,253,123,92,119,250,118,135,250,236,223,177,14,121,149,87,180,189,38,239,214,1,209,235,22,10,187,142,11,181,197,197,138,85,171,211,172,234,145,75,41,204,25,164,50,37,78,42,241,101,68,208,2,206,170,206,73,180,234,159,124,131,176,64,123,231,67,171,167,108,163,143,125,137,129,250,76,165,255,213,142,195,206,75,224,181,216,179,142,69,207,118,192,237,64,43,253,83,15,176,167,213,59,13,177,138,162,3,222,49,173,204,119,234,111,123,62,214,223,145,34,18,230,190,250,216,50,252,16,99,20,81,114,222,93,214,22,147,189,41,104,51,239,58,102,236,7,138,38,223,19,215,87,101,120,39,222,94,73,20,0,162,0,127,154,168,33,182,169,177,149,176,165,185,13,22,17,218,199,108,72,60,64,224,126,13,90,205,86,60,209,151,5,185,203,75,237,57,75,156,196,63,210,85,19,110,36,176,214,113,250,244,193,186,204,237,27,245,254,129,65,216,0,152,61,58,200,174,122,152,55,24,5,149,2,3,1,0,1,163,130,1,56,48,130,1,52,48,14,6,3,85,29,15,1,1,255,4,4,3,2,1,134,48,15,6,3,85,29,19,1,1,255,4,5,48,3,1,1,255,48,29,6,3,85,29,14,4,22,4,20,228,175,43,38,113,26,43,72,39,133,47,82,102,44,239,240,137,19,113,62,48,31,6,3,85,29,35,4,24,48,22,128,20,96,123,102,26,69,13,151,202,137,80,47,125,4,205,52,168,255,252,253,75,48,96,6,8,43,6,1,5,5,7,1,1,4,84,48,82,48,37,6,8,43,6,1,5,5,7,48,1,134,25,104,116,116,112,58,47,47,111,99,115,112,46,112,107,105,46,103,111,111,103,47,103,115,114,49,48,41,6,8,43,6,1,5,5,7,48,2,134,29,104,116,116,112,58,47,47,112,107,105,46,103,111,111,103,47,103,115,114,49,47,103,115,114,49,46,99,114,116,48,50,6,3,85,29,31,4,43,48,41,48,39,160,37,160,35,134,33,104,116,116,112,58,47,47,99,114,108,46,112,107,105,46,103,111,111,103,47,103,115,114,49,47,103,115,114,49,46,99,114,108,48,59,6,3,85,29,32,4,52,48,50,48,8,6,6,103,129,12,1,2,1,48,8,6,6,103,129,12,1,2,2,48,13,6,11,43,6,1,4,1,214,121,2,5,3,2,48,13,6,11,43,6,1,4,1,214,121,2,5,3,3,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,130,1,1,0,52,164,30,177,40,163,208,180,118,23,166,49,122,33,233,209,82,62,200,219,116,22,65,136,184,61,53,29,237,228,255,147,225,92,95,171,187,234,124,207,219,228,13,209,139,87,242,38,111,91,190,23,70,104,148,55,111,107,122,200,192,24,55,250,37,81,172,236,104,191,178,200,73,253,90,154,202,1,35,172,132,128,43,2,140,153,151,235,73,106,140,117,215,199,222,178,201,151,159,88,72,87,14,53,161,228,26,214,253,111,131,129,111,239,140,207,151,175,192,133,42,240,245,78,105,9,145,45,225,104,184,193,43,115,233,212,217,252,34,192,55,31,11,102,29,73,237,2,85,143,103,225,50,215,211,38,191,112,227,61,244,103,109,61,124,229,52,136,227,50,250,167,110,6,106,111,189,139,145,238,22,75,232,59,169,179,55,231,195,68,164,126,216,108,215,199,70,245,146,155,231,213,33,190,102,146,25,148,85,108,212,41,178,13,193,102,91,226,119,73,72,40,237,157,215,26,51,114,83,179,130,53,207,98,139,201,36,139,165,183,57,12,187,126,42,65,191,82,207,252,162,150,182,194,130,63,0,0);

const backChain = Certificate.from(certChain);
const verifyChain = await backChain.verify();

const blackCert = new Certificate;
debugger;




