const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const AlgorithmIdentifier = require("./AlgorithmIdentifier");

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
module.exports = SubjectPublicKeyInfo;
