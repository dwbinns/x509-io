//@ts-check
import { instance, optional, field, sequence, integer, octetString, explicit, oid, bitString, OID, DataValue, encoding, name } from "x690-io";
import PKCS8PrivateKeyInfo from "./PKCS8PrivateKeyInfo.js";

function packPublicKey(x, y) {
    return Buffer.concat([Buffer.from([4]), Buffer.from(x, "base64"), Buffer.from(y, "base64")]);
}


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
        // let bytes = instance(PrivateKeyInfo).encode(this).getBytes();
        // return new PKCS8PrivateKeyInfo(0, [PrivateKeyInfo.ecPublicKey, PrivateKeyInfo.prime256v1], bytes);
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
        return new ECPrivateKey(1, Buffer.from(d, "base64"), ECPrivateKey.prime256v1, packPublicKey(x, y));

    }
    static fromPKCS8(pkcs8Key) {
        let [type, curve] = pkcs8Key.privateKeyAlgorithm;
        if (!type.equals(ECPrivateKey.ecPublicKey)) {
            throw new Error("Not a elliptic curve");
        }
        let ecPrivateKey = instance(ECPrivateKey).decode(DataValue.read(pkcs8Key));
        if (!curve.equals(ECPrivateKey.prime256v1)) {
            throw new Error("Not a P-256 curve");
        }
        return ecPrivateKey;
    }
}
