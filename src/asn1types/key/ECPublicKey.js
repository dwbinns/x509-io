//@ts-check
import { bigInt, encoding, field, integer, name, sequence } from "x690-io";
import { bigintToBytes, bytesToBigInt } from "./X509ECSignature.js";
import { concatBytes } from "buffer-io";
import * as base64url from "@dwbinns/base/64url";


// https://www.secg.org/sec1-v2.pdf
// section 2.3.3 & 2.3.4
export default class ECPublicKey {

    constructor(x, y, keySize) {
        this.x = x;
        this.y = y;
        this.keySize = keySize;
    }

    static fromBytes(bytes, keySize) {
        if (bytes[0] != 4) throw new Error("Not an uncompressed public key");
        if (bytes.length != keySize * 2 + 1) throw new Error("Wrong length public key");
        return new ECPublicKey(
            bytesToBigInt(bytes.slice(1, keySize + 1)),
            bytesToBigInt(bytes.slice(keySize + 1)),
            keySize,
        );
    }

    static fromJWK({x, y}, keySize) {
        return new ECPublicKey(base64url.decode(x), base64url.decode(y), keySize);
    }

    toBytes() {
        return concatBytes([4], bigintToBytes(this.x, this.keySize), bigintToBytes(this.y, this.keySize))
    }

}
