//@ts-check
import { bigInt, encoding, field, integer, name, sequence } from "x690-io";


// https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.1
export default class RSAPublicKey {
    static [name] = "RSA PUBLIC KEY";

    constructor(modulus, publicExponent) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    static [encoding] = sequence(
        field('modulus', bigInt()),
        field('publicExponent', bigInt()),
    );


}
