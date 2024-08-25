import { decode, encoding, field, instance, integer, name, octetString, sequence } from "x690-io";
import AlgorithmIdentifier from "../certificate/AlgorithmIdentifier.js";
import ECPrivateKey from "./ECPrivateKey.js";
import RSAPrivateKey from "./RSAPrivateKey.js";


/*
JOSE registry:
https://www.iana.org/assignments/jose/jose.xhtml
*/
export default class PKCS8PrivateKeyInfo {
    // https://tools.ietf.org/html/rfc5208#section-5
    static [encoding] = sequence(
        field('version', integer()),
        field('privateKeyAlgorithm', instance(AlgorithmIdentifier)),
        field('privateKey', octetString())
    );

    static [name] = "PRIVATE KEY";

    constructor(version, privateKeyAlgorithm, privateKey) {
        this.version = version;
        this.privateKeyAlgorithm = privateKeyAlgorithm;
        this.privateKey = privateKey;
    }

    get privateKeyDetails() {
        if (this.privateKeyAlgorithm.algorithm.is("1.2.840.10045.2.1")) {
            return decode(this.privateKey, ECPrivateKey);
        }
        if (this.privateKeyAlgorithm.algorithm.is("1.2.840.113549.1.1.1")) {
            return decode(this.privateKey, RSAPrivateKey);
        }
    }
}
