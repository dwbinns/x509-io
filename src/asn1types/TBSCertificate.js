import { sequence, call, optional, field, instance } from 'structured-io';
import * as x690 from 'x690-io';import Name from './Name.js';
import Extension from './Extension.js';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import Validity from './Validity.js';
import SubjectPublicKeyInfo from './SubjectPublicKeyInfo.js';

class TBSCertificate {
    // https://tools.ietf.org/html/rfc5280#section-4.1.1.1
    static encoding = x690.sequence(

        field('version', optional(0, x690.explicit(0, x690.integer))),
        field('serialNumber', x690.use(x690.integer, x690.octetString)),
        field('signature', instance(AlgorithmIdentifier)),
        field('issuer', x690.sequenceOf(x690.setOf(instance(Name)))),
        field('validity', instance(Validity)),
        field('subject', x690.sequenceOf(x690.setOf(instance(Name)))),
        field('subjectPublicKeyInfo', instance(SubjectPublicKeyInfo)),
        field('issuerUniqueID', optional(undefined, x690.explicit(1, x690.octetString))),
        field('subjectUniqueID', optional(undefined, x690.explicit(2, x690.octetString))),
        field('extensions', x690.explicit(3, x690.sequenceOf(instance(Extension)), []))
    );
}
export default TBSCertificate;
