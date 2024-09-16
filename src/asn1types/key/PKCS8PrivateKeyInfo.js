//@ts-check
import * as x690 from 'x690-io';
import { decode, encoding, field, instance, integer, name, octetString, sequence } from "x690-io";
import AlgorithmIdentifier from "../certificate/AlgorithmIdentifier.js";
import ECPrivateKey from "./ECPrivateKey.js";
import RSAPrivateKey from "./RSAPrivateKey.js";
import X509ECSignature from './X509ECSignature.js';
import SubjectPublicKeyInfo from '../certificate/SubjectPublicKeyInfo.js';



const publicTransform = {
    "EC": ({ crv, x, y }) => ({ crv, x, y }),
    'RSA': ({ e, n }) => ({ e, n }),
}

const jwkToPublic = ({ kty = '', ...jwk }) => {
    let transform = publicTransform[kty];
    if (!transform) throw new Error("Unknown key type");
    return ({ kty, ...transform(jwk) });
}


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

    toBytes() {
        return x690.encode(this);
    }

    toPem() {
        return x690.Pem.encode(this);
    }

    static fromBytes(bytes) {
        return x690.decode(bytes, this);
    }

    static fromPem(pemText) {
        return x690.Pem.read(pemText).decodeSection(PKCS8PrivateKeyInfo);
    }

    toSPKI() {
        return new SubjectPublicKeyInfo(this.privateKeyAlgorithm, this.privateKeyDetails.toPublicKeyBytes());
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
