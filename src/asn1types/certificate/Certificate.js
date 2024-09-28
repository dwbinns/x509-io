//@ts-check
import * as x690 from 'x690-io';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import TBSCertificate from './TBSCertificate.js';

export default class Certificate {
    constructor(tbsCertificate, signatureAlgorithm, signature) {
        this.tbsCertificate = tbsCertificate;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }
    static [x690.encoding] = x690.sequence(
        x690.field('tbsCertificate', x690.instance(TBSCertificate)),
        x690.field('signatureAlgorithm', x690.instance(AlgorithmIdentifier)),
        x690.field('signature', x690.bitString())
    );

    static [x690.name] = "CERTIFICATE";

    toPem() {
        return x690.Pem.encode(this);
    }

    static importCertificate(pem) {
        return x690.Pem.read(pem).decodeSection(Certificate);
    }
}

