const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const AlgorithmIdentifier = require("./AlgorithmIdentifier");

class SubjectPublicKeyInfo {
    static encoding = x690.sequence(
        field('algorithm', instance(AlgorithmIdentifier)),
        field('publicKey', x690.bitString )
    );
}
module.exports = SubjectPublicKeyInfo;
