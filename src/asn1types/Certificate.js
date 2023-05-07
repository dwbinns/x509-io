import { field, instance } from 'structured-io';
import * as x690 from 'x690-io';import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import TBSCertificate from './TBSCertificate.js';

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
export default Certificate;
