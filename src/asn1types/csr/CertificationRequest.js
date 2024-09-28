import crypto from 'crypto';
import { write } from 'structured-io';
import * as x690 from 'x690-io';
import AlgorithmIdentifier from '../certificate/AlgorithmIdentifier.js';
import CertificationRequestInfo from './CertificationRequestInfo.js';

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

        sign.end(x690.encode(certificationRequestInfo));

        let signature = sign.sign({key: privateKey});

        return new CertificationRequest(
            certificationRequestInfo,
            AlgorithmIdentifier.ecdsaWithSha256,
            signature
        );
    }

    // https://tools.ietf.org/html/rfc2986
    static [x690.encoding] = x690.sequence(
        x690.field('certificationRequestInfo', x690.instance(CertificationRequestInfo)),
        x690.field('signatureAlgorithm', x690.instance(AlgorithmIdentifier)),
        x690.field('signature', x690.bitString() )
    );

    toPem() {
        return x690.Pem.encode(this);
    }

    getBytes() {
        return x690.encode(this);
    }

    static [x690.name] = "CERTIFICATE REQUEST";
}

export default CertificationRequest;
