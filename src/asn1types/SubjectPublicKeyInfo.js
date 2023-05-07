import { field, instance } from 'structured-io';
import * as x690 from 'x690-io';import AlgorithmIdentifier from './AlgorithmIdentifier.js';

class SubjectPublicKeyInfo {
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


    // https://tools.ietf.org/html/rfc5280#section-4.1.2.7
    static encoding = x690.sequence(
        field('algorithm', instance(AlgorithmIdentifier)),
        field('publicKey', x690.bitString )
    );
}
export default SubjectPublicKeyInfo;
