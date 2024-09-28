//@ts-check
import * as x690 from 'x690-io';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import X509ECSignature from '../key/X509ECSignature.js';
import RSAPublicKey from '../key/RSAPublicKey.js';
import ECPublicKey from '../key/ECPublicKey.js';

function arraysEqual(a1, a2) {
    return a1.length == a2.length && a1.every((v, i) => v === a2[i]);
}



export default class SubjectPublicKeyInfo {
    constructor(algorithm, publicKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
    }

    static ecPrime256v1(publicKey) {
        return new SubjectPublicKeyInfo(
            AlgorithmIdentifier.ecPrime256v1,
            publicKey,
        );
    }

    static rsa(publicKey) {
        return new SubjectPublicKeyInfo(
            AlgorithmIdentifier.rsa,
            publicKey,
        );
    }


    static [x690.name] = "PUBLIC KEY";

    // https://tools.ietf.org/html/rfc5280#section-4.1.2.7
    static [x690.encoding] = x690.sequence(
        x690.field('algorithm', x690.instance(AlgorithmIdentifier)),
        x690.field('publicKey', x690.bitString() )
    );

    static fromBytes(bytes) {
        return x690.decode(bytes, this);
    }

    compare(other) {
        if (!(other instanceof SubjectPublicKeyInfo)) return false;
        return other.algorithm.equals(this.algorithm) && arraysEqual(other.publicKey, this.publicKey);
    }

    unpack() {
        
    }

    toBytes() {
        return x690.encode(this);
    }

    

    toPem() {
        return x690.Pem.encode(this);
    }

    

    get publicKeyDetails() {
        if (this.algorithm.algorithm.is("1.2.840.10045.2.1")) {
            return ECPublicKey.fromBytes(this.publicKey, 32);
        }
        if (this.algorithm.algorithm.is("1.2.840.113549.1.1.1")) {
            return x690.decode(this.publicKey, RSAPublicKey);
        }
    }
}

