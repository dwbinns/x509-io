//@ts-check
import * as x690 from "x690-io";
import { bigInt, encoding, field, integer, name, sequence } from "x690-io";
import RSAPublicKey from "./RSAPublicKey.js";


export default class RSAPrivateKey {
    static [name] = "RSA PRIVATE KEY";

    modulus;
    publicExponent;

    static [encoding] = sequence(
        field('version', integer()),
        field('modulus', bigInt()),
        field('publicExponent', bigInt()),
        field('privateExponent', bigInt()),
        field('prime1', bigInt()),
        field('prime2', bigInt()),
        field('exponent1', bigInt()),
        field('exponent2', bigInt()),
        field('coefficient', bigInt()),
    );

    toPublicKey() {
        return new RSAPublicKey(this.modulus, this.publicExponent);
    }

    toPublicKeyBytes() {
        return x690.encode(this.toPublicKey());
    }
}
