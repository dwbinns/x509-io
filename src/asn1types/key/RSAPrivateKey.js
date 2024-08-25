//@ts-check
import { bigInt, encoding, field, integer, name, sequence } from "x690-io";


export default class RSAPrivateKey {
    static [name] = "RSA PRIVATE KEY";

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


}
