//@ts-check
import * as x690 from 'x690-io';
import { concatBytes } from 'buffer-io';


export function bytesToBigInt(bytes) {
    return [...bytes]
        .reduce(
            (result, byte) => result * 256n + BigInt(byte),
            0n
        )
}

export function bigintToBytes(bigInt, byteLength) {
    let result = new Uint8Array(byteLength);
    for (let i = byteLength - 1; i >= 0; i--) {
        result[i] = Number(bigInt & 0xffn);
        bigInt = bigInt >> 8n;
    }
    return result;
}



export default class X509ECSignature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }

    static fromWebCrypto(signatureBytes) {
        //IEEE P1363:
        return new X509ECSignature(bytesToBigInt(signatureBytes.slice(0, 32)), bytesToBigInt(signatureBytes.slice(32)));
    }

    static [x690.encoding] = x690.sequence(
        x690.field("r", x690.bigInt()),
        x690.field("s", x690.bigInt()),
    );

    toIEEEP1363() {
        return concatBytes(bigintToBytes(this.r, 32), bigintToBytes(this.s, 32));
    }
}
