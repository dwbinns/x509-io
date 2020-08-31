const { write, field, instance } = require('structured-io');
const x690 = require('x690-io');
const AlgorithmIdentifier = require("../AlgorithmIdentifier");
const CertificationRequestInfo = require("./CertificationRequestInfo");
const crypto = require("crypto");

class CertificationRequest {

    constructor(certificationRequestInfo, signatureAlgorithm, signature) {
        this.certificationRequestInfo = certificationRequestInfo;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;

    }

    static forNames(privateKey, publicKey, commonName, ...dnsNames) {
        return CertificationRequest.sign(
            CertificationRequestInfo.forNames(publicKey, commonName, ...dnsNames),
            privateKey
        );
    }

    static sign(certificationRequestInfo, privateKey) {
        const sign = crypto.createSign("SHA256");

        sign.end(write(certificationRequestInfo));

        let signature = sign.sign({key: privateKey});

        return new CertificationRequest(
            certificationRequestInfo,
            AlgorithmIdentifier.ecdsaWithSha256,
            signature
        );
    }

    // https://tools.ietf.org/html/rfc2986
    static encoding = x690.sequence(
        field('certificationRequestInfo', instance(CertificationRequestInfo)),
        field('signatureAlgorithm', instance(AlgorithmIdentifier)),
        field('signature', x690.bitString )
    );

    decodeContent() {
        return [this.signature, x690.any];
    }
}

module.exports = CertificationRequest;
