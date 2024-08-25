import * as x690 from 'x690-io';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import Extension from './Extension.js';
import RDNAttribute from './RDNAttribute.js';
import PublicKey from './PublicKey.js';
import Validity from './Validity.js';
import Name from './Name.js';

class TBSCertificate {
    constructor(init) {
        if (init) Object.assign(this, init);
    }


    getExtension(extensionType) {
        return this.extensions.find(extension => extension.extensionID.id == extensionType.ID).decodeExtension();
    }

    // https://tools.ietf.org/html/rfc5280#section-4.1.1.1
    static [x690.encoding] = x690.sequence(
        x690.field('version', x690.optional(x690.explicit(0, x690.integer()), 0)),
        x690.field('serialNumber', x690.bigInt()),
        x690.field('signature', x690.instance(AlgorithmIdentifier)),
        x690.field('issuer', x690.instance(Name)),
        x690.field('validity', x690.instance(Validity)),
        x690.field('subject', x690.instance(Name)),
        x690.field('subjectPublicKeyInfo', x690.instance(PublicKey)),
        x690.field('issuerUniqueID', x690.optional(x690.explicit(1, x690.octetString()))),
        x690.field('subjectUniqueID', x690.optional(x690.explicit(2, x690.octetString()))),
        x690.field('extensions', x690.explicit(3, x690.sequenceOf(x690.instance(Extension)), []))
    );
}
export default TBSCertificate;
