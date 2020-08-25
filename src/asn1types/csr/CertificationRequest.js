const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const AlgorithmIdentifier = require("../AlgorithmIdentifier");
const CertificationRequestInfo = require("./CertificationRequestInfo");

class CertificationRequest {
    // https://tools.ietf.org/html/rfc2986
    static encoding = x690.sequence(
        field('certificationRequestInfo', instance(CertificationRequestInfo)),
        field('signatureAlgorithm', instance(AlgorithmIdentifier)),
        field('signature', x690.bitString )
    );
}

module.exports = CertificationRequest;
