import { HexaDecimal } from "../src/dep.ts";
import { Finished } from "../src/finished.js";


const finishedMsg = HexaDecimal.fromString(
   `14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb
   dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07
   18`).byte

const finishedMsg_0 = Finished.fromHandshake(finishedMsg);

debugger;