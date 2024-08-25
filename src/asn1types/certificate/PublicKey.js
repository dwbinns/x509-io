import * as x690 from 'x690-io';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';

class PublicKey {
    constructor(algorithm, publicKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
    }

    static ecPrime256v1(publicKey) {
        return new PublicKey(
            AlgorithmIdentifier.ecPrime256v1,
            publicKey,
        );
    }

    static rsa(publicKey) {
        return new PublicKey(
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

    unpack() {
        if (publicKey[0] != 4) throw new Error("Not an uncompressed public key");
        if (publicKey.length != keySize * 2 + 1) throw new Error("Wrong length public key");
        return {
            x: base64url(publicKey.slice(1, keySize + 1)),
            y: base64url(publicKey.slice(keySize + 1)),
        };
    }
}
export default PublicKey;
