//@ts-check
import { bitString, DataValue, encode, encoding, explicit, field, instance, integer, name, octetString, oid, OID, optional, sequence } from "x690-io";
import ECPublicKey from "./ECPublicKey.js";
import SubjectPublicKeyInfo from "../certificate/SubjectPublicKeyInfo.js";
import AlgorithmIdentifier from "../certificate/AlgorithmIdentifier.js";
import PKCS8PrivateKeyInfo from "./PKCS8PrivateKeyInfo.js";

export default class ECPrivateKey {
    static ecPublicKey = new OID("1.2.840.10045.2.1");
    static prime256v1 = new OID("1.2.840.10045.3.1.7");
    // https://tools.ietf.org/html/rfc5915#section-3
    // generate key:
    // openssl ecparam -name secp256k1 -genkey -noout -out secp256k1-key.pem
    // inspect key:
    // openssl ec -in secp256k1-key.pem -text -noout
    constructor(version, privateKey, parameters, publicKey) {
        this.version = version;
        this.privateKey = privateKey;
        this.parameters = parameters;
        this.publicKey = publicKey;
    }

    makePKCS8() {
        return new PKCS8PrivateKeyInfo(0, AlgorithmIdentifier.elliptic(this.parameters), encode(this))
    }

    static [name] = "EC PRIVATE KEY";

    static [encoding] = sequence(
        field('version', integer()),
        field('privateKey', octetString()),
        field('parameters', optional(explicit(0, oid()), null)),
        field('publicKey', explicit(1, bitString()))
    );

    static fromJWK({ kty, crv, x, y, d }) {
        if (kty != "EC" || crv != "P-256")
            throw new Error("Not a P-256 EC key");
        return new ECPrivateKey(1, Buffer.from(d, "base64"), ECPrivateKey.prime256v1, ECPublicKey.fromJWK({ x, y }, 32).toBytes());

    }

    toPublicKeyBytes() {
        return this.publicKey;
    }
}
