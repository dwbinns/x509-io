const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const AlgorithmIdentifier = require("./AlgorithmIdentifier");
const TBSCertificate = require("./TBSCertificate");

class Certificate {
    static encoding = x690.sequence(
        field('tbsCertificate', instance(TBSCertificate)),
        field('signatureAlgorithm', instance(AlgorithmIdentifier)),
        field('signature', x690.bitString )
    );

    decodeContent() {
        return [this.signature, x690.any];
    }
}
module.exports = Certificate;
